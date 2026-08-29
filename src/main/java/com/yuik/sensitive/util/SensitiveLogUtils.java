package com.yuik.sensitive.util;

/**
 * 日志脱敏工具。
 *
 * <p><b>安全红线：</b>任何日志中禁止打印明文敏感数据、密钥或完整的 Base64 密文，
 * 只允许打印字段名、数据长度、脱敏后的摘要。
 *
 * @author sensitive-encrypt-spring-starter
 */
public final class SensitiveLogUtils {

    private SensitiveLogUtils() {
    }

    /**
     * 手机号等短字符串脱敏：保留前 3 位与后 4 位，中间以 **** 遮蔽。
     *
     * @param value 原始值
     * @return 脱敏后的字符串（绝不含完整原文）
     */
    public static String mask(String value) {
        if (value == null) {
            return "null";
        }
        if (value.length() <= 7) {
            return "****";
        }
        return value.substring(0, 3) + "****" + value.substring(value.length() - 4);
    }

    /**
     * 密文摘要：仅暴露长度与尾部 4 个字符，绝不打完整密文。
     *
     * @param base64Cipher Base64 密文
     * @return 如 "len=64,tail=Ab12"
     */
    public static String cipherSummary(String base64Cipher) {
        if (base64Cipher == null) {
            return "null";
        }
        String tail = base64Cipher.length() > 8
                ? base64Cipher.substring(base64Cipher.length() - 4) : base64Cipher;
        return "len=" + base64Cipher.length() + ",tail=" + tail;
    }

    /**
     * 值摘要：用于日志记录字段值类型与长度（不含内容）。
     *
     * @param value 任意值
     * @return 类型 + 长度描述
     */
    public static String describe(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String) {
            return "String(len=" + ((String) value).length() + ")";
        }
        return value.getClass().getSimpleName();
    }
}