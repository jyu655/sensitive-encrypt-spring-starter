package com.yuik.sensitive.crypto;

import java.util.Arrays;
import java.util.Base64;

/**
 * 密文编解码器：负责密文结构（版本 + IV + 密文）的打包 / 解包。
 *
 * <p>密文结构（Base64 编码前，即本类操作的原始字节）：
 * <pre>
 *   [1 字节:版本长度 N] + [N 字节:版本字符串 UTF-8] + [12 字节:随机 IV] + [密文 + 16 字节 GCM Tag]
 * </pre>
 *
 * <p>版本号内嵌于密文：密钥轮换后，旧数据仍可按版本号取回旧密钥解密（无感轮换的基础）。
 *
 * @author sensitive-encrypt-spring-starter
 */
public final class CiphertextCodec {

    /** GCM 推荐 IV 长度（字节）。 */
    public static final int IV_LENGTH = 12;

    /** 版本长度字段占 1 字节，最大 255。 */
    private static final int MAX_VERSION_BYTES = 255;

    /** 头部固定开销 = 版本长度字段 + IV。 */
    private static final int HEADER_OVERHEAD = 1 + IV_LENGTH;

    private CiphertextCodec() {
    }

    /**
     * 打包：版本 + IV + 密文 → 标准密文原始字节。
     *
     * @param versionBytes 版本字符串 UTF-8 字节（1 ~ 255 字节）
     * @param iv           随机 IV（必须恰为 {@link #IV_LENGTH} 字节）
     * @param ciphertext   GCM 密文（含 Tag）
     * @return 打包后的密文原始字节
     * @throws IllegalArgumentException 参数结构非法时抛出
     */
    public static byte[] pack(byte[] versionBytes, byte[] iv, byte[] ciphertext) {
        if (versionBytes == null || versionBytes.length == 0 || versionBytes.length > MAX_VERSION_BYTES) {
            throw new IllegalArgumentException("版本字节长度必须在 1~" + MAX_VERSION_BYTES + " 之间: "
                    + (versionBytes == null ? 0 : versionBytes.length));
        }
        if (iv == null || iv.length != IV_LENGTH) {
            throw new IllegalArgumentException("IV 长度必须为 " + IV_LENGTH + " 字节: "
                    + (iv == null ? 0 : iv.length));
        }
        if (ciphertext == null || ciphertext.length == 0) {
            throw new IllegalArgumentException("密文不能为空");
        }
        byte[] out = new byte[1 + versionBytes.length + iv.length + ciphertext.length];
        out[0] = (byte) versionBytes.length;
        System.arraycopy(versionBytes, 0, out, 1, versionBytes.length);
        System.arraycopy(iv, 0, out, 1 + versionBytes.length, iv.length);
        System.arraycopy(ciphertext, 0, out, 1 + versionBytes.length + iv.length, ciphertext.length);
        return out;
    }

    /**
     * 解包：标准密文原始字节 → 版本 / IV / 密文。
     *
     * @param raw 密文原始字节（Base64 解码后）
     * @return 解析结果
     * @throws IllegalArgumentException 结构非法时抛出（如长度不足、版本长度字段越界）
     */
    public static Payload unpack(byte[] raw) {
        if (raw == null || raw.length < HEADER_OVERHEAD) {
            throw new IllegalArgumentException("密文结构不完整: 原始长度 " + (raw == null ? 0 : raw.length)
                    + " < 最小开销 " + HEADER_OVERHEAD);
        }
        int versionLength = raw[0] & 0xFF;
        if (versionLength <= 0 || versionLength > MAX_VERSION_BYTES
                || 1 + versionLength + IV_LENGTH > raw.length) {
            throw new IllegalArgumentException("密文版本长度字段非法: " + versionLength);
        }
        byte[] version = Arrays.copyOfRange(raw, 1, 1 + versionLength);
        byte[] iv = Arrays.copyOfRange(raw, 1 + versionLength, 1 + versionLength + IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(raw, 1 + versionLength + IV_LENGTH, raw.length);
        if (ciphertext.length == 0) {
            throw new IllegalArgumentException("密文主体为空");
        }
        return new Payload(version, iv, ciphertext);
    }

    /**
     * 启发式判断一个字符串是否已是本组件的密文（防重复加密）。
     *
     * <p>// DESIGN-NOTE: 更新场景下实体可能携带已落库的密文（如先查后改），
     * 若直接再次加密会产生双重加密脏数据。本方法通过 Base64 解码 + 结构校验
     * 识别已有密文；正常明文极少满足该结构，误判概率可忽略。
     *
     * @param base64Value 待判断字符串
     * @return true 表示结构上已是标准密文
     */
    public static boolean looksLikeCiphertext(String base64Value) {
        if (base64Value == null || base64Value.isEmpty()) {
            return false;
        }
        try {
            byte[] raw = Base64.getDecoder().decode(base64Value);
            // 最小结构 = 版本长度字段 + 版本 + IV + GCM Tag（密文主体至少 16 字节）
            if (raw.length < HEADER_OVERHEAD + 16) {
                return false;
            }
            int versionLength = raw[0] & 0xFF;
            if (versionLength <= 0 || versionLength > MAX_VERSION_BYTES
                    || 1 + versionLength + IV_LENGTH > raw.length) {
                return false;
            }
            int cipherLength = raw.length - (1 + versionLength + IV_LENGTH);
            if (cipherLength < 16) {
                return false;
            }
            // DESIGN-NOTE: M5 加固 —— 版本段必须为可打印 ASCII（组件版本号如 "v1"/"2024-06"）。
            // 随机 Base64 文本同时满足"结构合法 + 版本可打印"的概率可忽略，
            // 杜绝合法 Base64 明文被误判为密文而静默跳过加密。
            for (int i = 1; i < 1 + versionLength; i++) {
                int c = raw[i] & 0xFF;
                if (c < 0x20 || c > 0x7E) {
                    return false;
                }
            }
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** 解包结果：版本 / IV / 密文。 */
    public static final class Payload {
        private final byte[] version;
        private final byte[] iv;
        private final byte[] ciphertext;

        Payload(byte[] version, byte[] iv, byte[] ciphertext) {
            this.version = version;
            this.iv = iv;
            this.ciphertext = ciphertext;
        }

        public byte[] getVersion() {
            return version;
        }

        public byte[] getIv() {
            return iv;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }
    }
}