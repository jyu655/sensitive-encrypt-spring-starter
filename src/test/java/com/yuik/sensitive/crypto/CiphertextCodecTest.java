package com.yuik.sensitive.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CiphertextCodecTest {

    private final byte[] version = "v1".getBytes(StandardCharsets.UTF_8);
    private final byte[] iv = new byte[CiphertextCodec.IV_LENGTH];
    private final byte[] ciphertext = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    @Test
    void packAndUnpackRoundTrip() {
        byte[] packed = CiphertextCodec.pack(version, iv, ciphertext);
        assertEquals(1 + version.length + CiphertextCodec.IV_LENGTH + ciphertext.length, packed.length);
        assertEquals(version.length, packed[0] & 0xFF);

        CiphertextCodec.Payload payload = CiphertextCodec.unpack(packed);
        assertArrayEquals(version, payload.getVersion());
        assertArrayEquals(iv, payload.getIv());
        assertArrayEquals(ciphertext, payload.getCiphertext());
    }

    @Test
    void packRejectsWrongIvLength() {
        assertThrows(IllegalArgumentException.class,
                () -> CiphertextCodec.pack(version, new byte[8], ciphertext));
    }

    @Test
    void packRejectsEmptyVersion() {
        assertThrows(IllegalArgumentException.class,
                () -> CiphertextCodec.pack(new byte[0], iv, ciphertext));
    }

    @Test
    void unpackRejectsTooShortRaw() {
        assertThrows(IllegalArgumentException.class,
                () -> CiphertextCodec.unpack(new byte[]{1, 2, 3}));
    }

    @Test
    void unpackRejectsInvalidVersionLengthField() {
        // 版本长度字段 = 0
        byte[] raw = new byte[1 + CiphertextCodec.IV_LENGTH + 16];
        raw[0] = 0;
        assertThrows(IllegalArgumentException.class, () -> CiphertextCodec.unpack(raw));

        // 版本长度字段超出实际长度
        raw[0] = (byte) 250;
        assertThrows(IllegalArgumentException.class, () -> CiphertextCodec.unpack(raw));
    }

    @Test
    void looksLikeCiphertextDetectsValidCiphertext() {
        byte[] packed = CiphertextCodec.pack(version, iv, ciphertext);
        String b64 = Base64.getEncoder().encodeToString(packed);
        assertTrue(CiphertextCodec.looksLikeCiphertext(b64));
    }

    @Test
    void looksLikeCiphertextRejectsPlaintextAndGarbage() {
        assertFalse(CiphertextCodec.looksLikeCiphertext("hello world"));
        assertFalse(CiphertextCodec.looksLikeCiphertext(""));
        assertFalse(CiphertextCodec.looksLikeCiphertext(null));
        // 合法 Base64 但结构不是标准密文（长度不足）
        assertFalse(CiphertextCodec.looksLikeCiphertext(Base64.getEncoder().encodeToString(new byte[]{1, 2})));
    }

    @Test
    void looksLikeCiphertextRejectsUnprintableVersion() {
        // M5 加固：版本段包含不可打印字节 → 判非密文（防止合法 Base64 明文被误判跳过加密）
        byte[] raw = new byte[1 + 2 + CiphertextCodec.IV_LENGTH + 16];
        raw[0] = 2;                    // 版本长度 = 2
        raw[1] = (byte) 0x01;          // 不可打印
        raw[2] = 'x';
        assertFalse(CiphertextCodec.looksLikeCiphertext(Base64.getEncoder().encodeToString(raw)));
    }

    @Test
    void looksLikeCiphertextRejectsShortCiphertext() {
        // M5 加固：密文主体不足 16 字节（GCM Tag 最小长度）→ 判非密文
        byte[] raw = new byte[1 + 2 + CiphertextCodec.IV_LENGTH + 15];
        raw[0] = 2;
        raw[1] = 'v';
        raw[2] = '1';
        assertFalse(CiphertextCodec.looksLikeCiphertext(Base64.getEncoder().encodeToString(raw)));
    }

    @Test
    void looksLikeCiphertextAcceptsPrintableVersionWithEnoughBody() {
        // 结构完全合法（可打印版本 + 密文主体 >= 16B）→ 判为密文
        byte[] raw = new byte[1 + 2 + CiphertextCodec.IV_LENGTH + 16];
        raw[0] = 2;
        raw[1] = 'v';
        raw[2] = '1';
        assertTrue(CiphertextCodec.looksLikeCiphertext(Base64.getEncoder().encodeToString(raw)));
    }

    @Test
    void multipleIvProduceDifferentCiphertext() {
        byte[] iv2 = Arrays.copyOf(iv, iv.length);
        iv2[0] = (byte) 99;
        byte[] p1 = CiphertextCodec.pack(version, iv, ciphertext);
        byte[] p2 = CiphertextCodec.pack(version, iv2, ciphertext);
        assertFalse(Arrays.equals(p1, p2));
    }
}