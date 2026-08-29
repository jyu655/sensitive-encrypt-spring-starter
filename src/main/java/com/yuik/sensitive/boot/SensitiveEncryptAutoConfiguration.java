package com.yuik.sensitive.boot;

import com.yuik.sensitive.config.SensitiveEncryptConfiguration;
import com.yuik.sensitive.key.CachedKeyManager;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Import;

/**
 * Spring Boot 自动装配入口：引入 jar 即生效，<b>无需</b>手动添加 @EnableSensitiveEncrypt。
 *
 * <p>兼容性设计：
 * <ul>
 *     <li><b>Boot 2.7+ / Boot 3.x</b>：通过 spring.factories 与
 *         AutoConfiguration.imports 双通道注册（见 META-INF 资源）；</li>
 *     <li><b>回退保护</b>：{@link ConditionalOnMissingBean} —— 若业务方已通过
 *         @EnableSensitiveEncrypt 或自定义配置注册了 {@link CachedKeyManager}，
 *         本自动装配自动让位，绝不重复注册；</li>
 *     <li><b>纯 Spring 隔离</b>：本类仅被 Boot 的 AutoConfigurationImportSelector 加载，
 *         纯 Spring 应用（无 spring-boot-autoconfigure）永远不会触达本类，
 *         继续使用 @EnableSensitiveEncrypt 即可，两种风格并存。</li>
 * </ul>
 *
 * <p>// DESIGN-NOTE: 为什么直接 @Import(SensitiveEncryptConfiguration) 而非复制 Bean 定义？
 * Spring 的 ConfigurationClassParser 对同一个配置类去重，即使 @EnableSensitiveEncrypt
 * 与本自动装配同时生效，核心配置也只会被处理一次，不会产生重复 Bean。
 *
 * <p>Boot 配置项（通过 Environment 读取，支持 application.yml 与配置中心）：
 * <ul>
 *     <li>sensitive.encrypt.decrypt-fail-placeholder：解密失败占位符，默认 ***</li>
 * </ul>
 * 密钥仍必须来自 KeyProvider（环境变量 / KMS / HSM），禁止写入配置文件（安全红线 R1）。
 *
 * @author sensitive-encrypt-spring-starter
 */
@AutoConfiguration
@ConditionalOnClass(SensitiveEncryptConfiguration.class)
@ConditionalOnMissingBean(CachedKeyManager.class)
@Import(SensitiveEncryptConfiguration.class)
public class SensitiveEncryptAutoConfiguration {
}