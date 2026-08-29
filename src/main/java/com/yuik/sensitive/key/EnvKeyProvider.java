package com.yuik.sensitive.key;

import java.util.Base64;
import java.util.Locale;

/**
 * 默认密钥提供者：从<b>环境变量</b>读取密钥（Base64 编码）。
 *
 * <p>变量命名规则（别名规范化：大写 + 连字符转下划线）：
 * <pre>
 *   别名 "db-phone"      → 当前密钥    SENSITIVE_KEY_DB_PHONE
 *                         当前版本    SENSITIVE_KEY_VERSION_DB_PHONE（默认 "v1"）
 *                         历史密钥    SENSITIVE_KEY_DB_PHONE_V1、_V2 ...
 * </pre>
 *
 * <p>// DESIGN-NOTE: 别名规范化。POSIX 环境变量名不允许出现连字符 '-'
 * （bash 中 export FOO-BAR=1 会被解析为减法表达式），因此统一转为下划线。
 *
 * <p>// DESIGN-NOTE: 系统属性回退。除 System.getenv 外，允许同名的 JVM 系统属性
 * （-DSENSITIVE_KEY_DB_PHONE=...）作为回退来源，便于 CI / 单元测试注入；
 * 系统属性同样<b>不属于</b>业务配置文件，不违反密钥零硬编码红线。
 *
 * @author sensitive-encrypt-spring-starter
 */
public class EnvKeyProvider implements VersionedKeyProvider {

    private static final String PREFIX = "SENSITIVE_KEY_";
    private static final String VERSION_PREFIX = "SENSITIVE_KEY_VERSION_";
    private static final String DEFAULT_VERSION = "v1";

    @Override
    public byte[] getKeyBytes(String keyAlias) {
        String varName = PREFIX + normalize(keyAlias);
        String value = firstNonBlank(System.getenv(varName), System.getProperty(varName));
        if (value == null) {
            throw new IllegalStateException("未配置密钥: 环境变量/系统属性 [" + varName + "] 不存在，"
                    + "请通过 KeyProvider 提供密钥（禁止硬编码到代码或配置文件）");
        }
        return decodeBase64(value, varName);
    }

    @Override
    public byte[] getKeyBytes(String keyAlias, String keyVersion) {
        String varName = PREFIX + normalize(keyAlias) + "_" + normalize(keyVersion);
        String value = firstNonBlank(System.getenv(varName), System.getProperty(varName));
        if (value == null) {
            throw new IllegalStateException("未配置历史密钥: 环境变量/系统属性 [" + varName + "] 不存在");
        }
        return decodeBase64(value, varName);
    }

    @Override
    public String getCurrentKeyVersion(String keyAlias) {
        String varName = VERSION_PREFIX + normalize(keyAlias);
        String value = firstNonBlank(System.getenv(varName), System.getProperty(varName));
        return value == null ? DEFAULT_VERSION : value.trim();
    }

    private static String normalize(String s) {
        return s == null ? "" : s.trim().toUpperCase(Locale.ROOT).replace('-', '_');
    }

    private static byte[] decodeBase64(String value, String varName) {
        try {
            return Base64.getDecoder().decode(value.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("密钥 [" + varName + "] 必须是合法的 Base64 编码", e);
        }
    }

    private static String firstNonBlank(String first, String second) {
        if (first != null && !first.trim().isEmpty()) {
            return first;
        }
        if (second != null && !second.trim().isEmpty()) {
            return second;
        }
        return null;
    }

    /** 仅返回实现名，不包含任何密钥内容。 */
    @Override
    public String toString() {
        return "EnvKeyProvider";
    }
}