package com.yuik.sensitive.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标注在 Controller 方法<b>参数</b>上，表示该入参对象（如 {@code @RequestBody} 请求体）
 * 中的 {@link EncryptField} 字段在进入业务逻辑前需要解密。
 *
 * <p>组件在调用目标方法前，对参数对象进行递归解密（就地修改参数对象）。
 *
 * <p>示例：
 * <pre>
 *     &#64;PostMapping("/save")
 *     public Result save(&#64;RequestBody &#64;DecryptParam UserDTO user) { ... }
 * </pre>
 *
 * @author sensitive-encrypt-spring-starter
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface DecryptParam {
}