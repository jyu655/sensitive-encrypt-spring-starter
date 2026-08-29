package com.yuik.sensitive.annotation;

import com.yuik.sensitive.config.SensitiveEncryptConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 一键开启敏感数据透明加解密组件。
 *
 * <p>通过 {@link Import} 引入核心配置 {@link SensitiveEncryptConfiguration}：
 * <ul>
 *     <li>强制开启 {@code @EnableAspectJAutoProxy}，防止业务方漏配导致 AOP 切面失效；</li>
 *     <li>注册 KeyProvider / CachedKeyManager / EncryptorFactory / SensitiveCryptoService；</li>
 *     <li>注册 SqlSessionFactoryBeanPostProcessor，无侵入地向 MyBatis 追加加密拦截器；</li>
 *     <li>注册 SensitiveApiAspect（仅当 spring-web 存在时）。</li>
 * </ul>
 *
 * <p>用法：在业务方任意 {@code @Configuration} 类上标注本注解即可，例如：
 * <pre>
 *     &#64;Configuration
 *     &#64;EnableSensitiveEncrypt
 *     public class AppConfig { ... }
 * </pre>
 *
 * @author sensitive-encrypt-spring-starter
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(SensitiveEncryptConfiguration.class)
public @interface EnableSensitiveEncrypt {
}