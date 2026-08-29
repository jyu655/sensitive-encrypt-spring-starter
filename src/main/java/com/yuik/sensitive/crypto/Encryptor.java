package com.yuik.sensitive.crypto;

/**
 * 加解密器 SPI。
 *
 * <p>实现必须遵循组件安全红线：
 * <ul>
 *     <li>仅使用 AES/GCM/NoPadding（AEAD），IV 每次随机生成（12 字节）；</li>
 *     <li>密钥以 byte[] 接收，Cipher 初始化并完成加解密后立即 Arrays.fill 擦除；</li>
 *     <li>密文遵循 {@link CiphertextCodec} 标准结构，携带版本号支持密钥轮换。</li>
 * </ul>
 *
 * @author sensitive-encrypt-spring-starter
 */
public interface Encryptor {

    /**
     * 加密明文。
     *
     * @param plaintext 明文（null / 空串直接原样返回，不产生密文）
     * @param keyAlias  密钥别名
     * @return Base64 编码的标准密文
     * @throws CryptoException 加密失败（密钥缺失、算法不可用等）
     */
    String encrypt(String plaintext, String keyAlias);

    /**
     * 解密密文。
     *
     * @param ciphertext Base64 编码的标准密文（null / 空串直接原样返回）
     * @param keyAlias   密钥别名
     * @return 明文
     * @throws DecryptionException 解密失败（密文被篡改 AEADBadTagException、结构非法、
     *                             历史密钥缺失等），由上层统一降级处理
     */
    String decrypt(String ciphertext, String keyAlias);
}