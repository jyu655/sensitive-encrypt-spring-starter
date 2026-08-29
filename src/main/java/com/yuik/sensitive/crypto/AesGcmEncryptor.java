package com.yuik.sensitive.crypto;

import com.yuik.sensitive.key.CachedKeyManager;

import javax.crypto.Cipher;
import javax.crypto.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * AES/GCM 加解密器 —— 组件唯一的对称加密实现。
 *
 * <p><b>算法红线：</b>仅允许 {@code AES/GCM/NoPadding}（AEAD 模式）。
 * 禁止 ECB / CBC / DES / 3DES：ECB 相同明文产生相同密文、模式泄露；
 * CBC 无完整性校验且存在 padding oracle 攻击面。GCM 通过 128bit Tag 同时提供
 * 机密性 + 完整性，密文被篡改会抛出 {@code AEADBadTagException} 被上层检出。
 *
 * <p><b>内存安全红线：</b>密钥以 byte[] 接收，Cipher 初始化并完成加解密后，
 * 在 finally 中立即 {@link Arrays#fill(byte[], byte)} 覆写本次使用的所有临时
 * 密钥 / 敏感字节数组，防止密钥驻留 JVM 堆被 Heap Dump 泄露。
 *
 * <p>线程安全：Cipher 实例每次操作新建（Cipher 本身非线程安全），本类无共享可变状态。
 *
 * @author sensitive-encrypt-spring-starter
 */
public class AesGcmEncryptor implements Encryptor {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String AES = "AES";
    private static final int GCM_TAG_BITS = 128;

    private final CachedKeyManager keyManager;
    private final SecureRandom secureRandom = new SecureRandom();

    public AesGcmEncryptor(CachedKeyManager keyManager) {
        this.keyManager = keyManager;
    }

    @Override
    public String encrypt(String plaintext, String keyAlias) {
        if (plaintext == null || plaintext.isEmpty()) {
            return plaintext;
        }
        // DESIGN-NOTE: 密钥以防御性拷贝接收（CachedKeyManager 只交付拷贝），
        // 本方法使用完毕后必须擦除，绝不允许把缓存主拷贝暴露到加解密路径之外
        byte[] keyBytes = keyManager.getKeyBytes(keyAlias);
        byte[] iv = new byte[CiphertextCodec.IV_LENGTH];
        byte[] ciphertext = null;
        byte[] packed = null;
        byte[] versionBytes = null;
        try {
            secureRandom.nextBytes(iv); // 每次加密随机 IV，禁止复用
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, AES),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            versionBytes = keyManager.getCurrentKeyVersion(keyAlias).getBytes(StandardCharsets.UTF_8);
            packed = CiphertextCodec.pack(versionBytes, iv, ciphertext);
            return Base64.getEncoder().encodeToString(packed);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoException("加密失败: alias=" + keyAlias, e);
        } finally {
            // DESIGN-NOTE: 内存安全红线 —— Cipher 初始化并完成加解密后立即擦除
            // 本次使用的密钥拷贝与所有敏感中间字节数组
            Arrays.fill(keyBytes, (byte) 0);
            if (iv != null) {
                Arrays.fill(iv, (byte) 0);
            }
            if (ciphertext != null) {
                Arrays.fill(ciphertext, (byte) 0);
            }
            if (packed != null) {
                Arrays.fill(packed, (byte) 0);
            }
            if (versionBytes != null) {
                Arrays.fill(versionBytes, (byte) 0);
            }
        }
    }

    @Override
    public String decrypt(String ciphertext, String keyAlias) {
        if (ciphertext == null || ciphertext.isEmpty()) {
            return ciphertext;
        }
        byte[] raw = null;
        byte[] keyBytes = null;
        byte[] plain = null;
        CiphertextCodec.Payload payload = null;
        byte[] versionBytes = null;
        try {
            try {
                raw = Base64.getDecoder().decode(ciphertext);
            } catch (IllegalArgumentException e) {
                throw new DecryptionException("密文不是合法 Base64: alias=" + keyAlias, e);
            }
            try {
                payload = CiphertextCodec.unpack(raw);
            } catch (IllegalArgumentException e) {
                throw new DecryptionException("密文结构非法: alias=" + keyAlias, e);
            }
            versionBytes = payload.getVersion();
            String version = new String(versionBytes, StandardCharsets.UTF_8);
            // 按密文内嵌版本号取密钥：轮换后旧数据仍可解密
            keyBytes = keyManager.getKeyBytes(keyAlias, version);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, AES),
                    new GCMParameterSpec(GCM_TAG_BITS, payload.getIv()));
            plain = cipher.doFinal(payload.getCiphertext());
            return new String(plain, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            // DESIGN-NOTE: AEADBadTagException（密文被篡改 / 密钥不匹配 / 密钥版本错误）等
            // 一律包装为 DecryptionException 向上传递，由 SensitiveCryptoService 统一降级，
            // 禁止直接抛出 RuntimeException 中断业务
            throw new DecryptionException("解密失败: alias=" + keyAlias + "（可能密文被篡改或密钥不匹配）", e);
        } finally {
            // DESIGN-NOTE: 内存安全红线 —— 擦除本次解密使用的密钥拷贝与所有敏感中间数组
            if (raw != null) {
                Arrays.fill(raw, (byte) 0);
            }
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
            if (plain != null) {
                Arrays.fill(plain, (byte) 0);
            }
            if (payload != null) {
                if (versionBytes != null) {
                    Arrays.fill(versionBytes, (byte) 0);
                }
                Arrays.fill(payload.getIv(), (byte) 0);
                Arrays.fill(payload.getCiphertext(), (byte) 0);
            }
        }
    }
}