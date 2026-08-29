package com.yuik.sensitive.boot;

import com.yuik.sensitive.annotation.EnableSensitiveEncrypt;
import com.yuik.sensitive.aspect.SensitiveApiAspect;
import com.yuik.sensitive.crypto.EncryptorFactory;
import com.yuik.sensitive.key.CachedKeyManager;
import com.yuik.sensitive.mybatis.MybatisEncryptInterceptor;
import com.yuik.sensitive.mybatis.SqlSessionFactoryBeanPostProcessor;
import com.yuik.sensitive.service.SensitiveCryptoService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Spring Boot 自动装配测试（ApplicationContextRunner）：
 * 验证「引入 jar 即生效，无需 @EnableSensitiveEncrypt」以及回退/去重机制。
 */
class SensitiveEncryptAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SensitiveEncryptAutoConfiguration.class));

    @Test
    void autoConfigRegistersAllCoreBeans() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(CachedKeyManager.class);
            assertThat(context).hasSingleBean(EncryptorFactory.class);
            assertThat(context).hasSingleBean(SensitiveCryptoService.class);
            assertThat(context).hasSingleBean(MybatisEncryptInterceptor.class);
            assertThat(context).hasSingleBean(SqlSessionFactoryBeanPostProcessor.class);
            // spring-web 在测试类路径上 → API 切面按需注册成功
            assertThat(context).hasSingleBean(SensitiveApiAspect.class);
        });
    }

    @Test
    void placeholderReadableFromBootEnvironment() {
        runner.withPropertyValues("sensitive.encrypt.decrypt-fail-placeholder=******")
                .run(context -> {
                    SensitiveCryptoService service = context.getBean(SensitiveCryptoService.class);
                    assertThat(service.getDecryptFailPlaceholder()).isEqualTo("******");
                });
    }

    /** 业务方显式使用 @EnableSensitiveEncrypt 时，自动装配必须让位（不重复注册）。 */
    @Configuration
    @EnableSensitiveEncrypt
    static class ExplicitConfig {
        @Bean
        public String marker() {
            return "manual";
        }
    }

    @Test
    void autoConfigBacksOffWhenExplicitlyEnabled() {
        runner.withUserConfiguration(ExplicitConfig.class)
                .run(context -> {
                    // 只存在一份核心 Bean（来自 @EnableSensitiveEncrypt 的导入，自动装配已回退）
                    assertThat(context).hasSingleBean(CachedKeyManager.class);
                    assertThat(context).hasSingleBean(SensitiveCryptoService.class);
                    assertThat(context).hasBean("marker");
                });
    }
}