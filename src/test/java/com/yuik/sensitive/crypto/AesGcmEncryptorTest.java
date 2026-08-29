package com.yuik.sensitive.crypto;

import com.yuik.sensitive.TestKeys;
import com.yuik.sensitive.key.CachedKeyManager;
import com.yuik.sensitive.key.EnvKeyProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AesGcmEncryptorTest {

    private CachedKeyManager keyManager;
    private AesGcmEncryptor encryptor;

    @BeforeEach
    void setUp() {
        TestKeys.installEnvKey(TestKeys.ALIAS, TestKeys.KEY_B64);
        keyManager = new CachedKeyManager(new EnvKeyProvider());
        keyManager.afterPropertiesSet();
        encryptor = new AesGcmEncryptor(keyManager);
    }

    @AfterEach
    void tearDown() {
        keyManager.destroy();
        TestKeys.uninstall(TestKeys.ALIAS);
        TestKeys.uninstall(TestKeys.API_ALIAS);
    }

    @Test
    void roundTrip() {
        String plaintext = "13800138000";
        String cipher = encryptor.encrypt(plaintext, TestKeys.ALIAS);
        assertNotNull(cipher);
        assertNotEquals(plaintext, cipher);
        assertEquals(plaintext, encryptor.decrypt(cipher, TestKeys.ALIAS));
    }

    @Test
    void ciphertextStructureIsVersionPlusIvPlusBody() {
        String cipher = encryptor.encrypt("hello-sensitive", TestKeys.ALIAS);
        byte[] raw = Base64.getDecoder().decode(cipher);
        CiphertextCodec.Payload payload = CiphertextCodec.unpack(raw);
        // 版本 = v1
        assertEquals(TestKeys.V1, new String(payload.getVersion(), StandardCharsets.UTF_8));
        // IV 必须恰为 12 字节
        assertEquals(CiphertextCodec.IV_LENGTH, payload.getIv().length);
        // 密文主体非空（含 GCM Tag）
        assertTrue(payload.getCiphertext().length > 0);
    }

    @Test
    void samePlaintextProducesDifferentCiphertext() {
        String c1 = encryptor.encrypt("same-value", TestKeys.ALIAS);
        String c2 = encryptor.encrypt("same-value", TestKeys.ALIAS);
        assertNotEquals(c1, c2); // 随机 IV：密文必须不同
    }

    @Test
    void tamperedCiphertextFailsDecryption() {
        String cipher = encryptor.encrypt("integrity-check", TestKeys.ALIAS);
        // 篡改 Base64 末尾字符，破坏 GCM Tag
        char[] chars = cipher.toCharArray();
        chars[chars.length - 2] = chars[chars.length - 2] == 'A' ? 'B' : 'A';
        String tampered = new String(chars);
        assertThrows(DecryptionException.class, () -> encryptor.decrypt(tampered, TestKeys.ALIAS));
    }

    @Test
    void nullAndEmptyPassthrough() {
        assertNull(encryptor.encrypt(null, TestKeys.ALIAS));
        assertEquals("", encryptor.encrypt("", TestKeys.ALIAS));
        assertNull(encryptor.decrypt(null, TestKeys.ALIAS));
        assertEquals("", encryptor.decrypt("", TestKeys.ALIAS));
    }

    @Test
    void invalidBase64FailsDecryption() {
        assertThrows(DecryptionException.class, () -> encryptor.decrypt("!!!not-base64!!!", TestKeys.ALIAS));
    }

    @Test
    void unconfiguredAliasFailsDecryption() {
        // 密钥已被 CachedKeyManager 缓存（卸载系统属性不影响缓存），因此改用"从未配置的别名"验证失败路径
        String cipher = encryptor.encrypt("with-key-1", TestKeys.ALIAS);
        assertThrows(Exception.class, () -> encryptor.decrypt(cipher, "not-configured-alias"));
    }

    @Test
    void decryptWithDifferentKeyFails() {
        // 另一别名配置了不同密钥：GCM Tag 校验失败 → DecryptionException
        TestKeys.installEnvKey(TestKeys.API_ALIAS, TestKeys.KEY_B64_OTHER);
        String cipher = encryptor.encrypt("with-key-1", TestKeys.ALIAS);
        assertThrows(DecryptionException.class, () -> encryptor.decrypt(cipher, TestKeys.API_ALIAS));
    }

    @Test
    void unicodeRoundTrip() {
        String plaintext = "中文姓名张三 + emoji smile";
        String cipher = encryptor.encrypt(plaintext, TestKeys.ALIAS);
        assertEquals(plaintext, encryptor.decrypt(cipher, TestKeys.ALIAS));
    }
}