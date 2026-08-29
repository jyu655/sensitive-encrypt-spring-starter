package com.yuik.sensitive.mybatis;

import org.apache.ibatis.plugin.Interceptor;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;

import java.lang.reflect.Field;

/**
 * 无侵入的 MyBatis 拦截器注入器。
 *
 * <p>// DESIGN-NOTE: 核心设计 —— 业务方<b>无需</b>手动配置拦截器。
 * 本 BeanPostProcessor 在 SqlSessionFactoryBean 初始化前，
 * 通过反射读取其私有 plugins 字段（保留业务方已配置的拦截器），
 * 将 {@link MybatisEncryptInterceptor} <b>追加到末尾</b>，再 setPlugins 回写。
 *
 * <p>兼容性：
 * <ul>
 *     <li>MyBatis-Plus 的 {@code MybatisSqlSessionFactoryBean} 继承自 SqlSessionFactoryBean，
 *         instanceof 判断自动覆盖；</li>
 *     <li>plugins 字段在 mybatis-spring 各版本中均为 {@code private Interceptor[] plugins}，
 *         反射读取兼容性好于依赖未公开的 getter。</li>
 * </ul>
 *
 * @author sensitive-encrypt-spring-starter
 */
public class SqlSessionFactoryBeanPostProcessor implements BeanPostProcessor {

    private static final Logger log = LoggerFactory.getLogger(SqlSessionFactoryBeanPostProcessor.class);

    private final MybatisEncryptInterceptor interceptor;

    public SqlSessionFactoryBeanPostProcessor(MybatisEncryptInterceptor interceptor) {
        this.interceptor = interceptor;
    }

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        // beforeInitialization 先于 SqlSessionFactoryBean.afterPropertiesSet() 执行，
        // 保证拦截器在 SqlSessionFactory 构建（加载 plugins）之前注入
        if (bean instanceof SqlSessionFactoryBean) {
            appendInterceptor((SqlSessionFactoryBean) bean, beanName);
        }
        return bean;
    }

    private void appendInterceptor(SqlSessionFactoryBean factoryBean, String beanName) {
        try {
            Interceptor[] existing = readPlugins(factoryBean);
            if (contains(existing, interceptor)) {
                return; // 幂等保护：防止容器刷新导致重复注入
            }
            int oldLength = existing == null ? 0 : existing.length;
            Interceptor[] merged = new Interceptor[oldLength + 1];
            if (oldLength > 0) {
                System.arraycopy(existing, 0, merged, 0, oldLength);
            }
            merged[oldLength] = interceptor; // 追加到末尾
            factoryBean.setPlugins(merged);
            log.info("[SensitiveEncrypt] 已向 SqlSessionFactoryBean 追加 MybatisEncryptInterceptor, "
                    + "bean={}, 拦截器总数={}", beanName, merged.length);
        } catch (ReflectiveOperationException e) {
            // 注入失败直接失败启动（fail-fast）：宁可启动失败，也不允许敏感数据明文落库
            throw new IllegalStateException("注入 MybatisEncryptInterceptor 失败, bean=" + beanName, e);
        }
    }

    /**
     * 反射读取 SqlSessionFactoryBean 当前 plugins 数组。
     *
     * <p>// DESIGN-NOTE: 必须按 <b>运行时实际类</b>（最派生子类）向上查找 plugins 字段。
     * MyBatis-Plus 的 MybatisSqlSessionFactoryBean 自带私有 plugins 字段并重写 setPlugins()
     * 与 buildSqlSessionFactory()（只读自己的字段）；若读父类字段将拿到 null，
     * 导致追加后把业务方已配置的拦截器（如分页）整体覆盖丢失（H2 修复）。
     *
     * @param factoryBean 目标工厂 Bean（可能是 SqlSessionFactoryBean 或其子类）
     * @return 当前 plugins 数组（可能为 null）
     */
    private org.apache.ibatis.plugin.Interceptor[] readPlugins(SqlSessionFactoryBean factoryBean)
            throws ReflectiveOperationException {
        Field field = findPluginsField(factoryBean.getClass());
        field.setAccessible(true);
        return (org.apache.ibatis.plugin.Interceptor[]) field.get(factoryBean);
    }

    /** 从最派生子类开始向上查找 plugins 字段声明（覆盖父类同名字段）。 */
    private static Field findPluginsField(Class<?> type) throws NoSuchFieldException {
        Class<?> current = type;
        while (current != null && current != Object.class) {
            try {
                return current.getDeclaredField("plugins");
            } catch (NoSuchFieldException e) {
                current = current.getSuperclass();
            }
        }
        throw new NoSuchFieldException("SqlSessionFactoryBean 未找到 plugins 字段: " + type.getName());
    }

    private boolean contains(org.apache.ibatis.plugin.Interceptor[] plugins,
                             org.apache.ibatis.plugin.Interceptor target) {
        if (plugins == null) {
            return false;
        }
        for (org.apache.ibatis.plugin.Interceptor p : plugins) {
            if (p == target || (p != null && p.getClass() == target.getClass())) {
                return true;
            }
        }
        return false;
    }
}