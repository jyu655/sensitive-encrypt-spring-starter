package com.yuik.sensitive.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标注实体类中需要透明加解密的字段。
 *
 * <p><b>约束：</b>
 * <ul>
 *     <li>字段类型<b>必须为 String</b>，非 String 字段将被忽略；</li>
 *     <li>keyAlias 必须与 KeyProvider 中可解析的密钥别名一致（如环境变量
 *         {@code SENSITIVE_KEY_DB_PHONE} 对应别名 {@code db-phone}）。</li>
 * </ul>
 *
 * <p>示例：
 * <pre>
 *     &#64;EncryptField(keyAlias = "db-phone")
 *     private String phone;
 * </pre>
 *
 * @author sensitive-encrypt-spring-starter
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface EncryptField {

    /**
     * 密钥别名，用于从 KeyProvider 中获取对应密钥。
     *
     * @return 密钥别名（非空）
     */
    String keyAlias();
}