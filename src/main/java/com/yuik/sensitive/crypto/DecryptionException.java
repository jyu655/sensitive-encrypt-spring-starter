package com.yuik.sensitive.crypto;

/**
 * 解密失败异常（运行时）。
 *
 * <p>触发场景：密文被篡改（GCM Tag 校验失败 AEADBadTagException）、密文结构非法、
 * 历史明文脏数据、历史密钥缺失等。该异常<b>不允许</b>直接抛出到业务层，
 * 由 {@link com.yuik.sensitive.service.SensitiveCryptoService} 统一捕获并降级返回脱敏占位符。
 *
 * @author sensitive-encrypt-spring-starter
 */
public class DecryptionException extends CryptoException {

    private static final long serialVersionUID = 1L;

    public DecryptionException(String message) {
        super(message);
    }

    public DecryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}