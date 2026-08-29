package com.yuik.sensitive.key;

/**
 * 密钥提供者 SPI（Service Provider Interface）。
 *
 * <p><b>安全红线：</b>业务代码与任何配置文件中<b>禁止</b>出现明文密钥。
 * 密钥必须通过本接口从环境变量、KMS、HSM 等安全渠道动态获取。
 *
 * <p>默认实现为 {@link EnvKeyProvider}（读取 {@code SENSITIVE_KEY_{ALIAS}} 环境变量）。
 * 业务方只需在 Spring 容器中定义一个 {@code KeyProvider} Bean 即可覆盖默认实现
 * （如对接阿里云 KMS / 自建 KMS / HSM）。
 *
 * <p><b>实现约定：</b>
 * <ul>
 *     <li>返回的 {@code byte[]} 必须是<b>新分配的数组</b>（不共享内部状态），
 *         调用方会在使用完毕后立即 {@code Arrays.fill} 擦除，共享数组会导致误擦对方数据；</li>
 *     <li>返回的密钥长度必须为 AES 支持的 16 / 24 / 32 字节；</li>
 *     <li>如需支持历史版本解密，请同时实现 {@link VersionedKeyProvider}。</li>
 * </ul>
 *
 * @author sensitive-encrypt-spring-starter
 */
public interface KeyProvider {

    /**
     * 获取指定别名对应的<b>当前版本</b>密钥字节。
     *
     * @param keyAlias 密钥别名（如 "db-phone"）
     * @return 当前版本密钥字节（调用方负责擦除，禁止复用/共享数组）
     * @throws IllegalStateException 密钥不存在或无法获取时抛出
     */
    byte[] getKeyBytes(String keyAlias);

    /**
     * 获取指定别名对应的<b>当前密钥版本号</b>。
     *
     * @param keyAlias 密钥别名
     * @return 版本号字符串（如 "v1"、"v2"），用于密文版本标记与密钥轮换
     */
    String getCurrentKeyVersion(String keyAlias);
}