package com.yuik.sensitive.key;

import com.yuik.sensitive.TestKeys;
import com.yuik.sensitive.crypto.AesGcmEncryptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 密钥缓存与无感轮换测试。
 */
class CachedKeyManagerTest {

    /** 可变版本提供者：模拟 KMS 中的密钥轮换。 */
    private static class MutableVersionedProvider implements VersionedKeyProvider {
        volatile String version = TestKeys.V1;
        private final byte[] keyV1 = keyOf(0x11);
        private final byte[] keyV2 = keyOf(0x22);

        @Override
        public byte[] getKeyBytes(String keyAlias) {
            return TestKeys.V1.equals(version) ? keyV1 : keyV2;
        }

        @Override
        public String getCurrentKeyVersion(String keyAlias) {
            return version;
        }

        @Override
        public byte[] getKeyBytes(String keyAlias, String keyVersion) {
            return TestKeys.V1.equals(keyVersion) ? keyV1 : keyV2;
        }
    }

    private MutableVersionedProvider provider;
    private CachedKeyManager manager;

    @BeforeEach
    void setUp() {
        provider = new MutableVersionedProvider();
        manager = new CachedKeyManager(provider);
        manager.afterPropertiesSet();
    }

    @AfterEach
    void tearDown() {
        manager.destroy();
    }

    @Test
    void returnsDefensiveCopy() {
        byte[] first = manager.getKeyBytes(TestKeys.ALIAS);
        Arrays.fill(first, (byte) 0);
        // 主拷贝不受影响：第二次获取仍是原始密钥
        byte[] second = manager.getKeyBytes(TestKeys.ALIAS);
        assertNotEquals(0, second[0]);
        assertArrayEquals(provider.getKeyBytes(TestKeys.ALIAS), second);
    }

    @Test
    void rotationSwitchesCurrentKeyAndArchivesOld() {
        assertArrayEquals(keyOf(0x11), manager.getKeyBytes(TestKeys.ALIAS));

        provider.version = "v2";
        manager.refreshAll();

        assertArrayEquals(keyOf(0x22), manager.getKeyBytes(TestKeys.ALIAS));
        assertEquals("v2", manager.getCurrentKeyVersion(TestKeys.ALIAS));
        // 旧版本仍可通过版本号取回（历史数据解密）
        assertArrayEquals(keyOf(0x11), manager.getKeyBytes(TestKeys.ALIAS, "v1"));
    }

    @Test
    void oldCiphertextDecryptsAfterRotation() {
        AesGcmEncryptor encryptor = new AesGcmEncryptor(manager);
        String oldCipher = encryptor.encrypt("legacy-data", TestKeys.ALIAS); // 用 v1 加密

        provider.version = "v2";
        manager.refreshAll();

        // 轮换后旧密文仍能解密（密文内嵌 v1 版本号 -> 归档密钥）
        assertEquals("legacy-data", encryptor.decrypt(oldCipher, TestKeys.ALIAS));
        // 新数据用 v2 加密
        assertNotEquals(oldCipher, encryptor.encrypt("legacy-data", TestKeys.ALIAS));
    }

    @Test
    void unknownVersionWithoutProviderFails() {
        // 非 VersionedKeyProvider 场景：历史密钥缺失必须抛出（由上层降级）
        CachedKeyManager plain = new CachedKeyManager(new KeyProvider() {
            @Override
            public byte[] getKeyBytes(String keyAlias) {
                return keyOf(0x33);
            }

            @Override
            public String getCurrentKeyVersion(String keyAlias) {
                return "v1";
            }
        });
        assertThrows(IllegalStateException.class, () -> plain.getKeyBytes(TestKeys.ALIAS, "v9"));
    }

    @Test
    void rejectsInvalidKeyLength() {
        CachedKeyManager bad = new CachedKeyManager(new KeyProvider() {
            @Override
            public byte[] getKeyBytes(String keyAlias) {
                return new byte[]{1, 2, 3}; // 长度非法
            }

            @Override
            public String getCurrentKeyVersion(String keyAlias) {
                return "v1";
            }
        });
        assertThrows(IllegalStateException.class, () -> bad.getKeyBytes(TestKeys.ALIAS));
    }

    private static byte[] keyOf(int fill) {
        byte[] b = new byte[32];
        Arrays.fill(b, (byte) fill);
        return b;
    }
}