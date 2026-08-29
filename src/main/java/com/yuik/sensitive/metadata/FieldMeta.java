package com.yuik.sensitive.metadata;

import com.yuik.sensitive.annotation.EncryptField;

import java.lang.reflect.Field;

/**
 * 字段元数据：封装 {@link Field} 与其上的 {@link EncryptField} 注解，提供读写访问。
 *
 * <p>// DESIGN-NOTE: 反射性能优化 —— Field 与注解信息在首次访问类时解析并<b>缓存</b>，
 * 后续每次 SQL 执行 / AOP 拦截只做 get/set，绝不在热路径上重复反射解析注解。
 *
 * @author sensitive-encrypt-spring-starter
 */
public final class FieldMeta {

    private final Field field;
    private final EncryptField annotation;

    public FieldMeta(Field field) {
        this.field = field;
        this.annotation = field.getAnnotation(EncryptField.class);
        // 一次 setAccessible 永久生效（JDK17+ 业务类处于未命名模块，反射不受模块系统限制）
        this.field.setAccessible(true);
    }

    public Field getField() {
        return field;
    }

    public boolean isEncrypted() {
        return annotation != null;
    }

    public String getKeyAlias() {
        return annotation == null ? null : annotation.keyAlias();
    }

    public String getName() {
        return field.getName();
    }

    public Class<?> getType() {
        return field.getType();
    }

    public Object get(Object target) {
        try {
            return field.get(target);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("读取字段失败: " + field.getDeclaringClass().getName() + "#" + field.getName(), e);
        }
    }

    public void set(Object target, Object value) {
        try {
            field.set(target, value);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("写入字段失败: " + field.getDeclaringClass().getName() + "#" + field.getName(), e);
        }
    }

    @Override
    public String toString() {
        return "FieldMeta{" + field.getDeclaringClass().getSimpleName() + "#" + field.getName()
                + ", encrypted=" + isEncrypted() + '}';
    }
}