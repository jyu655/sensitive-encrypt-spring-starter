package com.yuik.sensitive.mybatis;

import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.plugin.Invocation;
import org.apache.ibatis.plugin.Plugin;
import org.junit.jupiter.api.Test;
import org.mybatis.spring.SqlSessionFactoryBean;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * H2 回归测试：模拟 MyBatis-Plus 的 MybatisSqlSessionFactoryBean 自带 plugins 字段并重写 setPlugins。
 * 验证 BeanPostProcessor 读取<b>子类</b>字段，保留业务既有拦截器并追加组件拦截器。
 */
class SqlSessionFactoryBeanPostProcessorTest {

    /** 模拟 MyBatis-Plus：子类自带 plugins 字段并重写 setPlugins / 只读自己的字段。 */
    public static class MybatisPlusLikeFactoryBean extends SqlSessionFactoryBean {
        private Interceptor[] plugins;

        @Override
        public void setPlugins(Interceptor[] plugins) {
            this.plugins = plugins;
        }

        public Interceptor[] getMyPlugins() {
            return plugins;
        }
    }

    static class BusinessPlugin implements Interceptor {
        @Override
        public Object intercept(Invocation invocation) throws Throwable {
            return invocation.proceed();
        }

        @Override
        public Object plugin(Object target) {
            return Plugin.wrap(target, this);
        }

        @Override
        public void setProperties(Properties properties) {
        }
    }

    @Test
    void preservesDerivedClassPluginsAndAppendsOurs() {
        MybatisPlusLikeFactoryBean factoryBean = new MybatisPlusLikeFactoryBean();
        BusinessPlugin business = new BusinessPlugin();
        factoryBean.setPlugins(new Interceptor[]{business}); // 业务方配置的既有拦截器（如分页）

        MybatisEncryptInterceptor ours = new MybatisEncryptInterceptor();
        SqlSessionFactoryBeanPostProcessor processor = new SqlSessionFactoryBeanPostProcessor(ours);

        Object processed = processor.postProcessBeforeInitialization(factoryBean, "mybatisPlusFactory");

        assertSame(factoryBean, processed);
        Interceptor[] merged = factoryBean.getMyPlugins();
        assertNotNull(merged);
        assertEquals(2, merged.length, "子类字段中应同时存在业务拦截器与组件拦截器");
        assertSame(business, merged[0], "业务既有拦截器必须保留在首位");
        assertSame(ours, merged[1], "组件拦截器必须追加到末尾");

        // 幂等：重复处理不重复注入
        processor.postProcessBeforeInitialization(factoryBean, "mybatisPlusFactory");
        assertEquals(2, factoryBean.getMyPlugins().length);
    }

    @Test
    void handlesPlainSqlSessionFactoryBeanWithExistingPlugins() {
        SqlSessionFactoryBean factoryBean = new SqlSessionFactoryBean();
        BusinessPlugin business = new BusinessPlugin();
        factoryBean.setPlugins(new Interceptor[]{business});

        MybatisEncryptInterceptor ours = new MybatisEncryptInterceptor();
        SqlSessionFactoryBeanPostProcessor processor = new SqlSessionFactoryBeanPostProcessor(ours);

        processor.postProcessBeforeInitialization(factoryBean, "plainFactory");

        // 读取父类字段验证合并结果
        try {
            java.lang.reflect.Field field = SqlSessionFactoryBean.class.getDeclaredField("plugins");
            field.setAccessible(true);
            Interceptor[] merged = (Interceptor[]) field.get(factoryBean);
            assertEquals(2, merged.length);
            assertSame(business, merged[0]);
            assertSame(ours, merged[1]);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("无法读取父类 plugins 字段", e);
        }
    }
}
