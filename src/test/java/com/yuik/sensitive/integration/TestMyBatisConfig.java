package com.yuik.sensitive.integration;

import com.yuik.sensitive.annotation.EnableSensitiveEncrypt;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;

/**
 * 纯 Spring + H2 + MyBatis 集成测试配置：
 * 业务方视角 —— 只加 @EnableSensitiveEncrypt，不手动配置任何拦截器。
 */
@Configuration
@EnableSensitiveEncrypt
public class TestMyBatisConfig {

    @Bean
    public DataSource dataSource() {
        return new DriverManagerDataSource("jdbc:h2:mem:sensitive;DB_CLOSE_DELAY=-1", "sa", "");
    }

    @Bean
    public SqlSessionFactoryBean sqlSessionFactoryBean(DataSource dataSource) {
        SqlSessionFactoryBean factoryBean = new SqlSessionFactoryBean();
        factoryBean.setDataSource(dataSource);
        org.apache.ibatis.session.Configuration configuration = new org.apache.ibatis.session.Configuration();
        configuration.setMapUnderscoreToCamelCase(true);
        configuration.addMapper(UserMapper.class);
        factoryBean.setConfiguration(configuration);
        return factoryBean;
    }

    @Bean
    public JdbcTemplate jdbcTemplate(DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }
}