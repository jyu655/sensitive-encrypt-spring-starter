package com.yuik.sensitive.service;

import com.yuik.sensitive.crypto.CiphertextCodec;
import com.yuik.sensitive.crypto.Encryptor;
import com.yuik.sensitive.crypto.EncryptorFactory;
import com.yuik.sensitive.metadata.FieldMeta;
import com.yuik.sensitive.metadata.FieldMetaCache;
import com.yuik.sensitive.util.DeepCopyUtils;
import com.yuik.sensitive.util.SensitiveLogUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Array;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Date;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

/**
 * 敏感数据加解密服务：MyBatis 拦截器与 API 切面的统一加解密入口。
 *
 * <p>职责：
 * <ul>
 *     <li>字段级加解密（{@link #encryptField} / {@link #decryptField}），含空值快速返回与防重复加密；</li>
 *     <li>扁平对象加解密（MyBatis 实体，{@link #encryptObjectFields} / {@link #decryptObjectFields}）；</li>
 *     <li>对象树递归加解密（API 出入参，{@link #encryptTree} / {@link #decryptTree}）；</li>
 *     <li>出参深拷贝 + 加密（{@link #deepCopyAndEncrypt}，AOP 深拷贝隔离）；</li>
 *     <li><b>解密异常降级</b>：捕获一切异常返回脱敏占位符，保证系统高可用。</li>
 * </ul>
 *
 * <p><b>日志脱敏红线：</b>本类所有日志仅打印字段名、长度、脱敏摘要，绝不打明文 / 完整密文。
 *
 * @author sensitive-encrypt-spring-starter
 */
public class SensitiveCryptoService {

    private static final Logger log = LoggerFactory.getLogger(SensitiveCryptoService.class);

    private final Encryptor encryptor;
    private final FieldMetaCache fieldMetaCache;

    /** 解密失败时返回的脱敏占位符（可通过 Environment 配置 sensitive.encrypt.decrypt-fail-placeholder 覆盖）。 */
    private String decryptFailPlaceholder = "***";

    public SensitiveCryptoService(EncryptorFactory encryptorFactory, FieldMetaCache fieldMetaCache) {
        this.encryptor = encryptorFactory.createEncryptor();
        this.fieldMetaCache = fieldMetaCache;
    }

    public void setDecryptFailPlaceholder(String decryptFailPlaceholder) {
        if (decryptFailPlaceholder != null && !decryptFailPlaceholder.isEmpty()) {
            this.decryptFailPlaceholder = decryptFailPlaceholder;
        }
    }

    public String getDecryptFailPlaceholder() {
        return decryptFailPlaceholder;
    }

    // ------------------------------------------------------------------
    // 字段级加解密
    // ------------------------------------------------------------------

    /**
     * 加密单个字段值。
     *
     * @param value      明文（null / 空串直接返回，不产生密文）
     * @param keyAlias   密钥别名
     * @param fieldLabel 字段标识（仅用于日志，不包含数据内容）
     * @return 密文
     */
    public String encryptField(String value, String keyAlias, String fieldLabel) {
        if (value == null || value.isEmpty()) {
            return value; // 空值快速返回
        }
        if (CiphertextCodec.looksLikeCiphertext(value)) {
            // DESIGN-NOTE: 防重复加密 —— 更新场景实体可能携带已落库的密文（先查后改），
            // 结构上已是密文的字符串直接跳过，避免双重加密产生脏数据
            return value;
        }
        String cipher = encryptor.encrypt(value, keyAlias);
        if (log.isDebugEnabled()) {
            log.debug("[SensitiveEncrypt] 字段 {} 加密完成, 明文长度={}, 密文摘要={}",
                    fieldLabel, value.length(), SensitiveLogUtils.cipherSummary(cipher));
        }
        return cipher;
    }

    /**
     * 解密单个字段值。
     *
     * <p>// DESIGN-NOTE: 异常降级 —— 密文被篡改（AEADBadTagException）、历史明文脏数据
     * （IllegalArgumentException）、历史密钥缺失等<b>一切异常</b>在此捕获：
     * 记录 WARN（仅字段名 + 异常类型 + 密文摘要），返回脱敏占位符，<b>禁止</b>抛出
     * RuntimeException 中断业务，保证系统高可用。
     *
     * @param value      密文（null / 空串直接返回）
     * @param keyAlias   密钥别名
     * @param fieldLabel 字段标识（仅用于日志）
     * @return 明文；解密失败时返回脱敏占位符
     */
    public String decryptField(String value, String keyAlias, String fieldLabel) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        // DESIGN-NOTE: 结构预检（M4 修复）—— 结构上不是本组件密文的值
        // （历史明文脏数据 / 已被解密过的值 / 普通文本）直接原样返回：
        // ① 幂等：同对象二次解密不会把明文破坏为占位符；
        // ② 容错：脏明文按"返回原值"语义保留，而不是被误报为密文篡改。
        if (!CiphertextCodec.looksLikeCiphertext(value)) {
            return value;
        }
        try {
            String plain = encryptor.decrypt(value, keyAlias);
            if (log.isDebugEnabled()) {
                log.debug("[SensitiveDecrypt] 字段 {} 解密完成, 明文长度={}",
                        fieldLabel, plain == null ? 0 : plain.length());
            }
            return plain;
        } catch (Exception e) {
            log.warn("[SensitiveDecrypt] 字段 {} 解密失败, 异常类型={}, 密文摘要={}, 已降级返回占位符",
                    fieldLabel, e.getClass().getSimpleName(), SensitiveLogUtils.cipherSummary(value));
            return decryptFailPlaceholder;
        }
    }

    // ------------------------------------------------------------------
    // 扁平对象加解密（MyBatis 实体：字段级，不递归嵌套对象）
    // ------------------------------------------------------------------

    /** 加密对象的所有 @EncryptField String 字段（用于 MyBatis 写库前）。 */
    public void encryptObjectFields(Object target) {
        transformFlat(target, true, null);
    }

    /** 解密对象的所有 @EncryptField String 字段（用于 MyBatis 查询结果）。 */
    public void decryptObjectFields(Object target) {
        transformFlat(target, false, null);
    }

    /**
     * 加密对象字段并记录原值快照（用于 MyBatis 写库后恢复业务实体，M3 隔离修复）。
     *
     * <p>调用方在 MyBatis 完成参数绑定（proceed）后必须调用 {@link #restoreFields}，
     * 将业务对象字段恢复为明文，避免 insert/update 后实体携带密文污染后续链路。
     *
     * @param target 参数对象（单实体 / Map / 集合 / 数组 / null）
     * @return 原值快照（可能为空快照，绝不返回 null）
     */
    public FieldSnapshot encryptObjectFieldsWithSnapshot(Object target) {
        FieldSnapshot snapshot = new FieldSnapshot();
        transformFlat(target, true, snapshot);
        return snapshot;
    }

    /**
     * 恢复快照中记录的原始字段值（best-effort：失败仅告警，不回滚事务）。
     *
     * @param snapshot 由 {@link #encryptObjectFieldsWithSnapshot} 返回的快照
     */
    public void restoreFields(FieldSnapshot snapshot) {
        if (snapshot == null) {
            return;
        }
        try {
            snapshot.restore();
        } catch (Exception e) {
            log.warn("[SensitiveEncrypt] 写库后恢复业务对象原始值失败: 异常类型={}", e.getClass().getSimpleName());
        }
    }

    /**
     * 扁平转换：支持单对象 / Map / 集合 / 数组，仅处理 @EncryptField String 字段，不递归嵌套 POJO。
     *
     * <p>// DESIGN-NOTE: 批量处理 —— ResultSetHandler 对 List 结果集逐元素调用本方法，
     * 字段元数据来自缓存，避免逐条反射带来的性能损耗。
     *
     * @param snapshot 非 null 时在加密同时记录原值（用于写库后恢复）；null 表示纯就地转换
     */
    private void transformFlat(Object target, boolean encrypt, FieldSnapshot snapshot) {
        if (target == null) {
            return;
        }
        if (target instanceof Map) {
            for (Object value : ((Map<?, ?>) target).values()) {
                transformFlat(value, encrypt, snapshot);
            }
            return;
        }
        if (target instanceof Iterable) {
            for (Object item : (Iterable<?>) target) {
                transformFlat(item, encrypt, snapshot);
            }
            return;
        }
        if (target.getClass().isArray()) {
            int length = Array.getLength(target);
            for (int i = 0; i < length; i++) {
                transformFlat(Array.get(target, i), encrypt, snapshot);
            }
            return;
        }
        if (!isPojo(target.getClass())) {
            return;
        }
        List<FieldMeta> encryptFields = fieldMetaCache.getEncryptFields(target.getClass());
        if (encryptFields.isEmpty()) {
            return;
        }
        for (FieldMeta fm : encryptFields) {
            Object value = fm.get(target);
            if (!(value instanceof String)) {
                continue; // @EncryptField 仅支持 String，非 String 字段跳过
            }
            if (snapshot != null && encrypt) {
                snapshot.record(fm, target, value);
            }
            String keyAlias = fm.getKeyAlias();
            fm.set(target, encrypt
                    ? encryptField((String) value, keyAlias, fm.getName())
                    : decryptField((String) value, keyAlias, fm.getName()));
        }
    }

    /**
     * 字段原值快照：记录加密前的原始值，供写库后恢复（M3 隔离）。
     */
    public static final class FieldSnapshot {
        private final List<Object[]> entries = new java.util.ArrayList<>();

        private void record(FieldMeta fieldMeta, Object target, Object originalValue) {
            entries.add(new Object[]{fieldMeta, target, originalValue});
        }

        private void restore() {
            for (Object[] entry : entries) {
                ((FieldMeta) entry[0]).set(entry[1], entry[2]);
            }
        }

        /** 是否记录过任何字段（无加密字段时为 true）。 */
        public boolean isEmpty() {
            return entries.isEmpty();
        }
    }

    // ------------------------------------------------------------------
    // 对象树递归加解密（API 出入参）
    // ------------------------------------------------------------------

    /**
     * 深拷贝后加密对象树（@EncryptResult 出参加密）。
     *
     * <p>// DESIGN-NOTE: 深拷贝隔离 —— 加密操作只作用于副本，原始业务对象不受影响，
     * 防止同一请求链路中后续逻辑（写日志、发 MQ）拿到密文引发 Bug。
     *
     * @param source 返回值
     * @return 加密后的深拷贝副本
     */
    public Object deepCopyAndEncrypt(Object source) {
        if (source == null) {
            return null;
        }
        Object copy = DeepCopyUtils.deepCopy(source);
        encryptTree(copy);
        return copy;
    }

    /**
     * 深拷贝后解密对象树（@DecryptParam 入参解密，非侵入）。
     *
     * <p>// DESIGN-NOTE: 非侵入原则 —— 解密作用于副本而非业务入参对象：
     * 原始入参（如 Jackson 反序列化的请求体）保持原样，业务方法收到解密后的副本。
     *
     * @param source 入参对象
     * @return 解密后的深拷贝副本
     */
    public Object deepCopyAndDecrypt(Object source) {
        if (source == null) {
            return null;
        }
        Object copy = DeepCopyUtils.deepCopy(source);
        decryptTree(copy);
        return copy;
    }

    /** 递归加密对象树（就地修改，用于已深拷贝的副本）。 */
    public void encryptTree(Object node) {
        walk(node, true, new IdentityHashMap<>());
    }

    /** 递归解密对象树（就地修改，用于 @DecryptParam 入参）。 */
    public void decryptTree(Object node) {
        walk(node, false, new IdentityHashMap<>());
    }

    /**
     * 递归遍历对象图：
     * <ul>
     *     <li>@EncryptField String 字段 → 加密 / 解密；</li>
     *     <li>嵌套 POJO / 集合 / Map / 数组 → 递归进入，支持任意深度的 DTO 嵌套；</li>
     *     <li>循环引用通过 IdentityHashMap 防止死循环。</li>
     * </ul>
     */
    private void walk(Object node, boolean encrypt, IdentityHashMap<Object, Boolean> visited) {
        if (node == null) {
            return;
        }
        Class<?> type = node.getClass();
        if (isLeaf(type)) {
            return;
        }
        if (visited.put(node, Boolean.TRUE) != null) {
            return; // 循环引用
        }
        if (node instanceof Map) {
            for (Object value : ((Map<?, ?>) node).values()) {
                walk(value, encrypt, visited);
            }
            return;
        }
        if (node instanceof Iterable) {
            for (Object item : (Iterable<?>) node) {
                walk(item, encrypt, visited);
            }
            return;
        }
        if (type.isArray()) {
            int length = Array.getLength(node);
            for (int i = 0; i < length; i++) {
                walk(Array.get(node, i), encrypt, visited);
            }
            return;
        }
        // DESIGN-NOTE: Spring MVC 常见返回类型 ResponseEntity / HttpEntity 的 body 才是业务数据。
        // 通过反射特判（不引入 spring-web 编译依赖，纯 MyBatis 项目加载本类不受影响），
        // 递归处理 body，避免 org.springframework.* 前缀排除导致明文泄露（H1 修复）。
        if (isHttpEntityWrapper(type)) {
            walk(httpEntityBody(node), encrypt, visited);
            return;
        }
        if (!isPojo(type)) {
            return;
        }
        for (FieldMeta fm : fieldMetaCache.getAllFields(type)) {
            Object value = fm.get(node);
            if (fm.isEncrypted() && value instanceof String) {
                fm.set(node, encrypt
                        ? encryptField((String) value, fm.getKeyAlias(), fm.getName())
                        : decryptField((String) value, fm.getKeyAlias(), fm.getName()));
            } else {
                walk(value, encrypt, visited);
            }
        }
    }

    // ------------------------------------------------------------------
    // 类型判断
    // ------------------------------------------------------------------

    /** Spring HTTP 包装类型（body 承载业务数据）。 */
    private static final String RESPONSE_ENTITY_CLASS = "org.springframework.http.ResponseEntity";
    private static final String HTTP_ENTITY_CLASS = "org.springframework.http.HttpEntity";

    private static boolean isHttpEntityWrapper(Class<?> type) {
        String name = type.getName();
        return RESPONSE_ENTITY_CLASS.equals(name) || HTTP_ENTITY_CLASS.equals(name);
    }

    /** 反射获取 ResponseEntity/HttpEntity 的 body（方法名 getBody 为 Spring 稳定契约）。 */
    private static Object httpEntityBody(Object node) {
        try {
            return node.getClass().getMethod("getBody").invoke(node);
        } catch (ReflectiveOperationException e) {
            log.warn("[SensitiveEncrypt] 读取 HTTP 包装类型 body 失败: {}", e.getClass().getSimpleName());
            return null;
        }
    }

    private static boolean isPojo(Class<?> type) {
        if (type.isPrimitive() || type.isEnum() || type.isArray()) {
            return false;
        }
        String name = type.getName();
        // 跳过 JDK / 框架内部类型，避免反射内部实现（如 Optional、Proxy 等）
        if (name.startsWith("java.") || name.startsWith("javax.")
                || name.startsWith("jdk.") || name.startsWith("sun.")
                || name.startsWith("org.springframework.")) {
            return false;
        }
        return true;
    }

    private static boolean isLeaf(Class<?> type) {
        return type.isPrimitive()
                || type.isEnum()
                || String.class.equals(type)
                || Boolean.class.equals(type)
                || Character.class.equals(type)
                || Class.class.equals(type)
                || Number.class.isAssignableFrom(type)
                || BigDecimal.class.equals(type)
                || BigInteger.class.equals(type)
                || Date.class.isAssignableFrom(type)
                || type.getName().startsWith("java.time.");
    }
}