package com.yuik.sensitive.key;

/**
 * 可选扩展接口：支持按<b>指定版本</b>获取历史密钥。
 *
 * <p>密钥轮换后，历史数据仍携带旧版本号，解密时需要按版本号取回旧密钥。
 * {@link com.yuik.sensitive.key.CachedKeyManager} 会优先使用缓存的历史密钥；
 * 缓存未命中时，若 KeyProvider 实现了本接口，则回调本方法补拉。
 *
 * <p>默认的 {@link EnvKeyProvider} 已实现本接口：
 * 历史密钥从环境变量 {@code SENSITIVE_KEY_{ALIAS}_{VERSION}} 读取。
 *
 * @author sensitive-encrypt-spring-starter
 */
public interface VersionedKeyProvider extends KeyProvider {

    /**
     * 获取指定别名 + 指定版本的密钥字节。
     *
     * @param keyAlias   密钥别名
     * @param keyVersion 密钥版本号（取自密文内嵌的版本标记）
     * @return 该版本密钥字节（调用方负责擦除，禁止复用/共享数组）
     * @throws IllegalStateException 该版本密钥不存在或无法获取时抛出
     */
    byte[] getKeyBytes(String keyAlias, String keyVersion);
}