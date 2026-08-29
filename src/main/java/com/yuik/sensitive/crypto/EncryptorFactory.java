package com.yuik.sensitive.crypto;

import com.yuik.sensitive.key.CachedKeyManager;

/**
 * 加解密器工厂：统一创建 {@link Encryptor} 实例。
 *
 * <p>// DESIGN-NOTE: 所有加解密入口（MyBatis 拦截器 / AOP 切面 / 业务直调）
 * 必须经由本工厂创建 Encryptor，禁止业务方绕过密钥管理直接 new Cipher。
 *
 * @author sensitive-encrypt-spring-starter
 */
public class EncryptorFactory {

    private final CachedKeyManager keyManager;

    public EncryptorFactory(CachedKeyManager keyManager) {
        this.keyManager = keyManager;
    }

    /**
     * 创建新的加解密器实例（AesGcmEncryptor 无共享可变状态，可安全复用）。
     *
     * @return Encryptor 实例
     */
    public Encryptor createEncryptor() {
        return new AesGcmEncryptor(keyManager);
    }
}