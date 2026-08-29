package com.yuik.sensitive.crypto;

/**
 * 加解密通用异常（运行时）。
 *
 * @author sensitive-encrypt-spring-starter
 */
public class CryptoException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}