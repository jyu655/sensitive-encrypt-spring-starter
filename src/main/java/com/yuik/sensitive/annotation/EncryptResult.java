package com.yuik.sensitive.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标注在 Controller / Service 方法上，表示<b>出参需要加密</b>。
 *
 * <p>组件会先对返回值执行<b>深拷贝</b>，再在副本上递归加密所有带有
 * {@link EncryptField} 注解的 String 字段，返回加密后的副本 ——
 * 原始业务对象（写日志、发 MQ 等后续链路使用的对象）不会被污染。
 *
 * <p>示例：
 * <pre>
 *     &#64;EncryptResult
 *     &#64;GetMapping("/user")
 *     public UserDTO getUser() { ... }
 * </pre>
 *
 * @author sensitive-encrypt-spring-starter
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface EncryptResult {
}