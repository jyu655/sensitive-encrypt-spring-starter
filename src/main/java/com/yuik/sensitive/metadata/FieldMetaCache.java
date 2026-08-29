package com.yuik.sensitive.metadata;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 类字段元数据缓存。
 *
 * <p>// DESIGN-NOTE: 核心性能设计 —— 使用 {@link ConcurrentHashMap} 缓存
 * {@code Class -> ClassMetadata}，绝对禁止在每次 SQL 执行或 AOP 拦截时实时反射
 * 解析注解。缓存 key 为 Class 对象本身，类卸载时条目随之失效，无内存泄漏。
 *
 * <p>本类为无状态单例（内部共享一份缓存），通过 {@link #getInstance()} 获取；
 * Spring 容器中的 Bean 亦指向同一实例，保证 MyBatis 拦截器与 AOP 切面共享缓存。
 *
 * @author sensitive-encrypt-spring-starter
 */
public final class FieldMetaCache {

    private static final FieldMetaCache DEFAULT = new FieldMetaCache();

    private final ConcurrentHashMap<Class<?>, ClassMetadata> cache = new ConcurrentHashMap<>();

    private FieldMetaCache() {
    }

    /**
     * 全局共享实例（线程安全）。
     *
     * @return FieldMetaCache 单例
     */
    public static FieldMetaCache getInstance() {
        return DEFAULT;
    }

    /**
     * 获取类的完整字段元数据（含加密字段列表），未命中时解析并缓存。
     *
     * @param type 目标类
     * @return 类元数据
     */
    public ClassMetadata getMetadata(Class<?> type) {
        if (type == null) {
            throw new IllegalArgumentException("type 不能为 null");
        }
        return cache.computeIfAbsent(type, FieldMetaCache::build);
    }

    /** 便捷方法：仅返回加密字段元数据。 */
    public List<FieldMeta> getEncryptFields(Class<?> type) {
        return getMetadata(type).encryptFields;
    }

    /** 便捷方法：仅返回全部字段元数据。 */
    public List<FieldMeta> getAllFields(Class<?> type) {
        return getMetadata(type).fields;
    }

    /** 手动清除指定类的缓存（一般不需要，供测试 / 热部署场景使用）。 */
    public void evict(Class<?> type) {
        if (type != null) {
            cache.remove(type);
        }
    }

    /**
     * 解析类元数据：沿继承链收集非 static / 非 transient / 非 synthetic 字段，
     * 子类同名字段覆盖父类（保留子类定义）。
     */
    private static ClassMetadata build(Class<?> type) {
        List<FieldMeta> fields = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        Class<?> current = type;
        while (current != null && current != Object.class && !isFrameworkSuperclass(current)) {
            for (Field f : current.getDeclaredFields()) {
                int mod = f.getModifiers();
                if (Modifier.isStatic(mod) || Modifier.isTransient(mod) || f.isSynthetic()) {
                    continue;
                }
                if (!seen.add(f.getName())) {
                    continue;
                }
                fields.add(new FieldMeta(f));
            }
            current = current.getSuperclass();
        }
        List<FieldMeta> encryptFields = new ArrayList<>();
        for (FieldMeta fm : fields) {
            if (fm.isEncrypted()) {
                encryptFields.add(fm);
            }
        }
        return new ClassMetadata(Collections.unmodifiableList(fields),
                Collections.unmodifiableList(encryptFields));
    }

    /**
     * 是否为 JDK / 框架超类。
     *
     * <p>// DESIGN-NOTE: L2 修复 —— 业务类若继承 java.* / 框架基类，
     * 继续上溯会对其 JDK 字段执行 setAccessible(true)，
     * 在 JDK 9+ 模块系统下抛出 InaccessibleObjectException；遇框架超类即停止上溯。
     */
    private static boolean isFrameworkSuperclass(Class<?> type) {
        String name = type.getName();
        return name.startsWith("java.") || name.startsWith("javax.")
                || name.startsWith("jdk.") || name.startsWith("sun.")
                || name.startsWith("org.springframework.");
    }

    /** 类的字段元数据集合。 */
    public static final class ClassMetadata {
        private final List<FieldMeta> fields;
        private final List<FieldMeta> encryptFields;

        ClassMetadata(List<FieldMeta> fields, List<FieldMeta> encryptFields) {
            this.fields = fields;
            this.encryptFields = encryptFields;
        }

        public List<FieldMeta> getFields() {
            return fields;
        }

        public List<FieldMeta> getEncryptFields() {
            return encryptFields;
        }
    }
}