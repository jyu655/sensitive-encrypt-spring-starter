package com.yuik.sensitive.key;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 密钥缓存管理器：缓存当前密钥 + 归档历史密钥，并定时刷新以支持<b>密钥无感轮换</b>。
 *
 * <p>职责：
 * <ul>
 *     <li>按别名缓存当前密钥（{@link ConcurrentHashMap}）；</li>
 *     <li>按 (别名, 版本) 归档历史密钥，轮换后旧密文仍可解密；</li>
 *     <li>{@link ScheduledExecutorService} 每 5 分钟检测一次版本变化，无感切换到新密钥；</li>
 *     <li>对外只交付<b>防御性拷贝</b>，主拷贝仅在刷新 / 销毁时被擦除。</li>
 * </ul>
 *
 * <p>// DESIGN-NOTE: 内存安全权衡。严格意义上「密钥不驻留堆」与「缓存密钥以支持轮换」是矛盾的，
 * 本组件的折中方案为：缓存中仅保留一份<b>主拷贝</b>（轮换解密所必需），
 * 所有对外交付的临时拷贝在使用完毕后立即被调用方 Arrays.fill 擦除；
 * 刷新替换主拷贝、销毁上下文时同样执行擦除，最大化压缩密钥在堆中的驻留窗口。
 *
 * @author sensitive-encrypt-spring-starter
 */
public class CachedKeyManager implements InitializingBean, DisposableBean {

    private static final Logger log = LoggerFactory.getLogger(CachedKeyManager.class);

    /** 首次刷新延迟（秒）。 */
    private static final long REFRESH_INITIAL_DELAY_SECONDS = 60;
    /** 刷新周期（秒）= 5 分钟。 */
    private static final long REFRESH_PERIOD_SECONDS = 300;
    /** 归档的历史密钥版本上限，超出后擦除最老版本。 */
    private static final int MAX_ARCHIVED_VERSIONS = 10;

    private static final char KEY_SEPARATOR = '\u0001';

    private final KeyProvider keyProvider;

    /** 别名 -> 当前版本主密钥字节（内部唯一主拷贝）。 */
    private final ConcurrentHashMap<String, byte[]> currentKeys = new ConcurrentHashMap<>();
    /** 别名+分隔符+版本 -> 归档密钥字节（历史主拷贝）。 */
    private final ConcurrentHashMap<String, byte[]> archivedKeys = new ConcurrentHashMap<>();
    /** 别名 -> 当前版本号。 */
    private final ConcurrentHashMap<String, String> currentVersions = new ConcurrentHashMap<>();
    /** 别名 -> 历史版本队列（按时间升序，用于裁剪）。 */
    private final ConcurrentHashMap<String, ArrayDeque<String>> versionHistory = new ConcurrentHashMap<>();
    /** 别名 -> 加载/刷新互斥锁，保证同一别名的加载与轮换串行化。 */
    private final ConcurrentHashMap<String, Object> aliasLocks = new ConcurrentHashMap<>();

    private volatile ScheduledExecutorService scheduler;
    private volatile boolean destroyed = false;

    public CachedKeyManager(KeyProvider keyProvider) {
        if (keyProvider == null) {
            throw new IllegalArgumentException("keyProvider 不能为 null");
        }
        this.keyProvider = keyProvider;
    }

    // ------------------------------------------------------------------
    // Spring 生命周期
    // ------------------------------------------------------------------

    @Override
    public void afterPropertiesSet() {
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "sensitive-key-refresh");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(this::refreshAll, REFRESH_INITIAL_DELAY_SECONDS,
                REFRESH_PERIOD_SECONDS, TimeUnit.SECONDS);
        log.info("[SensitiveKey] 密钥刷新任务已启动, 周期={}s", REFRESH_PERIOD_SECONDS);
    }

    @Override
    public void destroy() {
        destroyed = true;
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
        // DESIGN-NOTE: 内存安全 —— 上下文销毁时尽力擦除所有缓存主密钥，减少堆驻留
        for (byte[] b : currentKeys.values()) {
            Arrays.fill(b, (byte) 0);
        }
        for (byte[] b : archivedKeys.values()) {
            Arrays.fill(b, (byte) 0);
        }
        currentKeys.clear();
        archivedKeys.clear();
        currentVersions.clear();
        versionHistory.clear();
        aliasLocks.clear();
    }

    // ------------------------------------------------------------------
    // 对外 API
    // ------------------------------------------------------------------

    /**
     * 获取当前版本密钥的<b>防御性拷贝</b>。调用方在使用完毕后必须立即 Arrays.fill 擦除。
     *
     * @param keyAlias 密钥别名
     * @return 当前密钥拷贝（非空）
     */
    public byte[] getKeyBytes(String keyAlias) {
        ensureLoaded(keyAlias);
        byte[] master = currentKeys.get(keyAlias);
        return master == null ? null : master.clone();
    }

    /**
     * 获取<b>指定版本</b>密钥的防御性拷贝（用于解密历史密文）。
     *
     * @param keyAlias   密钥别名
     * @param keyVersion 版本号（取自密文内嵌标记）
     * @return 该版本密钥拷贝（非空）
     * @throws IllegalStateException 该版本密钥不可用时抛出（由上层统一降级处理）
     */
    public byte[] getKeyBytes(String keyAlias, String keyVersion) {
        if (keyVersion == null || keyVersion.trim().isEmpty() || keyVersion.equals(getCurrentKeyVersion(keyAlias))) {
            return getKeyBytes(keyAlias);
        }
        String cacheKey = cacheKey(keyAlias, keyVersion);
        // DESIGN-NOTE: L1 修复 —— 归档读取/补拉/裁剪全部置于同一别名锁内：
        // 避免 refresh 裁剪（remove + Arrays.fill 置零）与并发解密读取发生竞态，
        // 防止读到被置零的归档密钥导致瞬时解密失败。
        synchronized (lock(keyAlias)) {
            byte[] archived = archivedKeys.get(cacheKey);
            if (archived != null) {
                return archived.clone();
            }
            if (keyProvider instanceof VersionedKeyProvider) {
                byte[] fresh = ((VersionedKeyProvider) keyProvider).getKeyBytes(keyAlias, keyVersion);
                validateKeyLength(fresh, keyAlias, keyVersion);
                archivedKeys.put(cacheKey, fresh);
                recordVersion(keyAlias, keyVersion);
                // DESIGN-NOTE: L4 修复 —— 补拉历史版本后同步裁剪，防止两次定时刷新之间超上限
                pruneHistory(keyAlias);
                return fresh.clone();
            }
        }
        throw new IllegalStateException("密钥版本 [" + keyVersion + "] 不可用: 请实现 VersionedKeyProvider "
                + "或配置历史密钥 (alias=" + keyAlias + ")");
    }

    /** 当前密钥版本号。 */
    public String getCurrentKeyVersion(String keyAlias) {
        ensureLoaded(keyAlias);
        return currentVersions.get(keyAlias);
    }

    // ------------------------------------------------------------------
    // 内部实现
    // ------------------------------------------------------------------

    private void ensureLoaded(String alias) {
        if (currentKeys.containsKey(alias)) {
            return;
        }
        synchronized (lock(alias)) {
            if (currentKeys.containsKey(alias)) {
                return;
            }
            loadCurrent(alias);
        }
    }

    private void loadCurrent(String alias) {
        String version = keyProvider.getCurrentKeyVersion(alias);
        byte[] bytes = keyProvider.getKeyBytes(alias);
        validateKeyLength(bytes, alias, version);
        currentKeys.put(alias, bytes);
        currentVersions.put(alias, version);
        recordVersion(alias, version);
        log.debug("[SensitiveKey] 已加载密钥 alias={}, version={}, length={}B", alias, version, bytes.length);
    }

    /** 定时刷新入口（包级可见，供测试直接触发）。 */
    void refreshAll() {
        if (destroyed) {
            return;
        }
        try {
            for (String alias : currentKeys.keySet()) {
                try {
                    refreshAlias(alias);
                } catch (Exception e) {
                    log.warn("[SensitiveKey] 密钥刷新失败 alias={}, 原因: {}", alias, e.getMessage());
                }
            }
        } catch (Exception e) {
            log.warn("[SensitiveKey] 密钥刷新任务异常: {}", e.getMessage());
        }
    }

    private void refreshAlias(String alias) {
        String newVersion = keyProvider.getCurrentKeyVersion(alias);
        String oldVersion = currentVersions.get(alias);
        if (newVersion == null || newVersion.equals(oldVersion)) {
            return; // 版本无变化，无需轮换
        }
        byte[] newBytes = keyProvider.getKeyBytes(alias);
        validateKeyLength(newBytes, alias, newVersion);
        synchronized (lock(alias)) {
            byte[] oldBytes = currentKeys.get(alias);
            currentKeys.put(alias, newBytes);
            currentVersions.put(alias, newVersion);
            if (oldBytes != null) {
                // 老密钥归档保留，用于解密轮换前写入的历史数据
                archivedKeys.put(cacheKey(alias, oldVersion), oldBytes);
                recordVersion(alias, oldVersion);
                pruneHistory(alias);
            }
        }
        log.info("[SensitiveKey] 密钥无感轮换完成 alias={}, {} -> {}", alias, oldVersion, newVersion);
    }

    /** 记录版本并裁剪超限的历史版本（仅在同一别名锁内调用）。 */
    private void recordVersion(String alias, String version) {
        ArrayDeque<String> history = versionHistory.computeIfAbsent(alias, k -> new ArrayDeque<>());
        if (!history.contains(version)) {
            history.addLast(version);
        }
    }

    private void pruneHistory(String alias) {
        ArrayDeque<String> history = versionHistory.get(alias);
        while (history != null && history.size() > MAX_ARCHIVED_VERSIONS) {
            String oldest = history.pollFirst();
            byte[] removed = archivedKeys.remove(cacheKey(alias, oldest));
            if (removed != null) {
                // DESIGN-NOTE: 内存安全 —— 裁剪出缓存的历史密钥立即擦除，不留驻留窗口
                Arrays.fill(removed, (byte) 0);
            }
        }
    }

    private void validateKeyLength(byte[] keyBytes, String alias, String version) {
        if (keyBytes == null || (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32)) {
            throw new IllegalStateException("密钥长度不合法: alias=" + alias + ", version=" + version
                    + ", length=" + (keyBytes == null ? 0 : keyBytes.length) + "B, AES 要求 16/24/32 字节");
        }
    }

    private Object lock(String alias) {
        return aliasLocks.computeIfAbsent(alias, k -> new Object());
    }

    private static String cacheKey(String alias, String version) {
        return alias + KEY_SEPARATOR + version;
    }
}