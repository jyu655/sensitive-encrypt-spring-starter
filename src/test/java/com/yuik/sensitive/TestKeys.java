package com.yuik.sensitive;

import java.util.Base64;

/**
 * 测试密钥夹具：通过 JVM 系统属性注入（EnvKeyProvider 的环境变量回退渠道），
 * 绝不写进任何配置文件，符合组件密钥零硬编码红线。
 */
public final class TestKeys {

    public static final String ALIAS = "db-phone";
    public static final String API_ALIAS = "api-phone";
    public static final String V1 = "v1";

    public static final byte[] KEY_32B = keyBytes(32);
    public static final String KEY_B64 = Base64.getEncoder().encodeToString(KEY_32B);
    public static final byte[] KEY_32B_OTHER = keyBytesOther(32);
    public static final String KEY_B64_OTHER = Base64.getEncoder().encodeToString(KEY_32B_OTHER);

    private TestKeys() {
    }

    public static void installEnvKey(String alias, String keyB64) {
        System.setProperty(envName(alias), keyB64);
    }

    public static void installEnvVersion(String alias, String version) {
        System.setProperty(envName(alias) + "_VERSION", version);
    }

    public static void installHistoricalKey(String alias, String version, String keyB64) {
        System.setProperty(envName(alias) + "_" + version.toUpperCase(), keyB64);
    }

    public static void uninstall(String alias) {
        System.clearProperty(envName(alias));
        System.clearProperty(envName(alias) + "_VERSION");
    }

    private static String envName(String alias) {
        return "SENSITIVE_KEY_" + alias.toUpperCase().replace('-', '_');
    }

    private static byte[] keyBytes(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) (i + 1);
        }
        return b;
    }

    private static byte[] keyBytesOther(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) (0xFF - i);
        }
        return b;
    }
}