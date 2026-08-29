package com.yuik.sensitive.key;

import com.yuik.sensitive.TestKeys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EnvKeyProviderTest {

    private final EnvKeyProvider provider = new EnvKeyProvider();

    @BeforeEach
    void setUp() {
        TestKeys.installEnvKey(TestKeys.ALIAS, TestKeys.KEY_B64);
    }

    @AfterEach
    void tearDown() {
        TestKeys.uninstall(TestKeys.ALIAS);
    }

    @Test
    void readsCurrentKeyFromProperty() {
        byte[] key = provider.getKeyBytes(TestKeys.ALIAS);
        assertArrayEquals(TestKeys.KEY_32B, key);
    }

    @Test
    void missingKeyThrows() {
        TestKeys.uninstall(TestKeys.ALIAS);
        assertThrows(IllegalStateException.class, () -> provider.getKeyBytes(TestKeys.ALIAS));
    }

    @Test
    void defaultVersionIsV1() {
        assertEquals(TestKeys.V1, provider.getCurrentKeyVersion(TestKeys.ALIAS));
    }

    @Test
    void customVersionFromProperty() {
        TestKeys.installEnvVersion(TestKeys.ALIAS, "v9");
        assertEquals("v9", provider.getCurrentKeyVersion(TestKeys.ALIAS));
    }

    @Test
    void historicalVersionKeyReadable() {
        TestKeys.installHistoricalKey(TestKeys.ALIAS, "v1", TestKeys.KEY_B64_OTHER);
        byte[] key = provider.getKeyBytes(TestKeys.ALIAS, "v1");
        assertEquals(TestKeys.KEY_B64_OTHER, Base64.getEncoder().encodeToString(key));
    }

    @Test
    void aliasNormalizationHandlesDash() {
        // 别名 db-phone -> 环境变量名 SENSITIVE_KEY_DB_PHONE
        assertEquals(TestKeys.KEY_B64,
                Base64.getEncoder().encodeToString(provider.getKeyBytes("db-phone")));
    }

    @Test
    void returnsFreshArrayEachCall() {
        byte[] first = provider.getKeyBytes(TestKeys.ALIAS);
        byte[] second = provider.getKeyBytes(TestKeys.ALIAS);
        Arrays.fill(first, (byte) 0);
        // 第二次调用不受第一次擦除影响：每次返回独立数组
        assertArrayEquals(TestKeys.KEY_32B, second);
    }
}