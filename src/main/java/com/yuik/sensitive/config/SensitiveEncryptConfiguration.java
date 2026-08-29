package com.yuik.sensitive.config;

import com.yuik.sensitive.aspect.SensitiveApiAspect;
import com.yuik.sensitive.key.CachedKeyManager;
import com.yuik.sensitive.key.EnvKeyProvider;
import com.yuik.sensitive.key.KeyProvider;
import com.yuik.sensitive.crypto.EncryptorFactory;
import com.yuik.sensitive.metadata.FieldMetaCache;
import com.yuik.sensitive.mybatis.MybatisEncryptInterceptor;
import com.yuik.sensitive.mybatis.SqlSessionFactoryBeanPostProcessor;
import com.yuik.sensitive.service.SensitiveCryptoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.core.env.Environment;
import org.springframework.util.ClassUtils;

import java.util.List;

/**
 * 敏感数据透明加解密组件核心配置。
 *
 * <p>通过 {@link com.yuik.sensitive.annotation.EnableSensitiveEncrypt} 引入。
 *
 * <p>// DESIGN-NOTE: 强制 @EnableAspectJAutoProxy —— 放在组件配置内而非依赖业务方，
 * 防止业务方漏配 @EnableAspectJAutoProxy 导致 @EncryptResult / @DecryptParam 切面失效。
 *
 * <p>// DESIGN-NOTE: 默认 KeyProvider 解析 —— 默认的 EnvKeyProvider 不作为独立 Bean 注册，
 * 而是由 CachedKeyManager 构造时按需创建：若容器中存在业务自定义的 KeyProvider Bean
 * 则使用之（覆盖默认），否则回退 EnvKeyProvider。这样不存在类型歧义，也不依赖
 * Spring Boot 的 @ConditionalOnMissingBean（本组件为纯 Spring 环境）。
 *
 * @author sensitive-encrypt-spring-starter
 */
@Configuration
@EnableAspectJAutoProxy
public class SensitiveEncryptConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SensitiveEncryptConfiguration.class);

    /**
     * 密钥缓存管理器：解析最终使用的 KeyProvider（业务自定义 > 默认 EnvKeyProvider）。
     *
     * <p>CachedKeyManager 实现了 InitializingBean / DisposableBean，
     * Spring 会自动调用 afterPropertiesSet（启动刷新调度）与 destroy（停止调度 + 擦除缓存密钥）。
     */
    @Bean
    public CachedKeyManager cachedKeyManager(List<KeyProvider> userProviders) {
        if (userProviders.size() > 1) {
            throw new IllegalStateException("检测到多个 KeyProvider Bean（" + userProviders.size()
                    + " 个）：只允许定义一个 KeyProvider 覆盖默认实现，请删除多余的 Bean");
        }
        KeyProvider keyProvider = userProviders.isEmpty() ? new EnvKeyProvider() : userProviders.get(0);
        log.info("[SensitiveEncrypt] KeyProvider 已就绪: {}", keyProvider.getClass().getSimpleName());
        return new CachedKeyManager(keyProvider);
    }

    @Bean
    public EncryptorFactory encryptorFactory(CachedKeyManager keyManager) {
        return new EncryptorFactory(keyManager);
    }

    @Bean
    public FieldMetaCache fieldMetaCache() {
        return FieldMetaCache.getInstance();
    }

    @Bean
    public SensitiveCryptoService sensitiveCryptoService(EncryptorFactory encryptorFactory,
                                                         FieldMetaCache fieldMetaCache,
                                                         Environment environment) {
        SensitiveCryptoService service = new SensitiveCryptoService(encryptorFactory, fieldMetaCache);
        // 非密钥类配置项（解密失败占位符），通过 Spring Environment 读取，默认 ***
        service.setDecryptFailPlaceholder(
                environment.getProperty("sensitive.encrypt.decrypt-fail-placeholder", "***"));
        return service;
    }

    @Bean
    public MybatisEncryptInterceptor mybatisEncryptInterceptor(SensitiveCryptoService cryptoService) {
        MybatisEncryptInterceptor interceptor = new MybatisEncryptInterceptor();
        interceptor.setCryptoService(cryptoService);
        return interceptor;
    }

    @Bean
    public SqlSessionFactoryBeanPostProcessor sqlSessionFactoryBeanPostProcessor(MybatisEncryptInterceptor interceptor) {
        return new SqlSessionFactoryBeanPostProcessor(interceptor);
    }

    @Bean
    public SensitiveApiAspect sensitiveApiAspect(SensitiveCryptoService cryptoService) {
        // DESIGN-NOTE: 按需注册 —— 仅当 spring-web 存在（RestController 可解析）时才注册 API 切面，
        // 避免纯 MyBatis 项目因缺少 spring-web 导致切点解析失败
        if (!ClassUtils.isPresent("org.springframework.web.bind.annotation.RestController",
                getClass().getClassLoader())) {
            log.info("[SensitiveEncrypt] 未检测到 spring-web，跳过 SensitiveApiAspect 注册"
                    + "（MyBatis 落库加解密不受影响）");
            return null;
        }
        return new SensitiveApiAspect(cryptoService);
    }
}