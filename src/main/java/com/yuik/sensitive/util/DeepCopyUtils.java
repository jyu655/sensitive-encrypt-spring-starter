package com.yuik.sensitive.util;

import com.yuik.sensitive.metadata.FieldMeta;
import com.yuik.sensitive.metadata.FieldMetaCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 对象深拷贝工具。
 *
 * <p>// DESIGN-NOTE: 深拷贝隔离 —— @EncryptResult 出参加密前必须先深拷贝返回值，
 * 否则加密会直接修改原始业务对象，导致同一请求链路中后续逻辑
 * （写日志、发 MQ、再次使用）拿到的是密文而引发隐蔽 Bug。
 *
 * <p>支持：基本类型 / String / 装箱类型 / 枚举 / 集合 / Map / 数组 / POJO（含循环引用，
 * 通过 IdentityHashMap 记录已拷贝对象）；目标类型需具备无参构造器，
 * 否则退化为 Java 序列化拷贝，再不行则原样返回（共享引用）并记录 WARN。
 *
 * @author sensitive-encrypt-spring-starter
 */
public final class DeepCopyUtils {

    private static final Logger log = LoggerFactory.getLogger(DeepCopyUtils.class);

    private static final ConcurrentHashMap<Class<?>, Constructor<?>> CTOR_CACHE = new ConcurrentHashMap<>();
    private static final Set<Class<?>> WARNED_TYPES = ConcurrentHashMap.newKeySet();

    private DeepCopyUtils() {
    }

    /**
     * 深拷贝任意对象图。
     *
     * @param source 源对象
     * @return 深拷贝副本（不可深拷贝的类型原样返回）
     */
    public static Object deepCopy(Object source) {
        if (source == null) {
            return null;
        }
        return copy(source, new IdentityHashMap<>());
    }

    // ------------------------------------------------------------------
    // 内部实现
    // ------------------------------------------------------------------

    private static Object copy(Object o, IdentityHashMap<Object, Object> visited) {
        if (o == null) {
            return null;
        }
        Class<?> type = o.getClass();

        if (isImmutableLeaf(type)) {
            return o;
        }
        if (o instanceof Date) {
            return new Date(((Date) o).getTime());
        }
        if (type.isArray()) {
            return copyArray(o, type, visited);
        }
        if (o instanceof Map) {
            return copyMap((Map<?, ?>) o, visited);
        }
        if (o instanceof Collection) {
            return copyCollection((Collection<?>) o, visited);
        }
        // DESIGN-NOTE: Spring MVC 的 ResponseEntity 无无参构造器且业务 DTO 未必 Serializable，
        // 若不特判会退化为共享引用，导致 @EncryptResult 出参加密污染原始对象（H1 隔离修复）。
        // 反射构造 (body, HttpStatus) 新实例，不引入 spring-web 编译依赖。
        if (isResponseEntity(type)) {
            Object he = copyResponseEntity(o, type, visited);
            if (he != null) {
                return he;
            }
        }
        if (isJdkInternal(type)) {
            // JDK 内部类型（Optional、Pattern 等）不做深拷贝，避免模块反射限制
            return o;
        }
        Object existing = visited.get(o);
        if (existing != null) {
            return existing; // 循环引用：返回已创建的副本
        }
        return copyPojo(o, type, visited);
    }

    private static Object copyPojo(Object o, Class<?> type, IdentityHashMap<Object, Object> visited) {
        Constructor<?> ctor = getNoArgConstructor(type);
        if (ctor == null) {
            if (o instanceof Serializable) {
                try {
                    return serializeCopy(o);
                } catch (Exception e) {
                    log.warn("[DeepCopy] 序列化拷贝失败 type={}, 原因: {}", type.getName(), e.getMessage());
                }
            }
            warnOnce(type);
            return o; // 无法深拷贝：原样返回（共享引用），调用方需确保不修改其内部状态
        }
        try {
            Object copy = ctor.newInstance();
            visited.put(o, copy);
            for (FieldMeta fm : FieldMetaCache.getInstance().getAllFields(type)) {
                Object value = fm.get(o);
                fm.set(copy, copy(value, visited));
            }
            return copy;
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException e) {
            throw new IllegalStateException("深拷贝失败: " + type.getName(), e);
        }
    }

    private static Object copyArray(Object o, Class<?> type, IdentityHashMap<Object, Object> visited) {
        int length = Array.getLength(o);
        Object copy = Array.newInstance(type.getComponentType(), length);
        for (int i = 0; i < length; i++) {
            Array.set(copy, i, copy(Array.get(o, i), visited));
        }
        return copy;
    }

    private static Object copyCollection(Collection<?> o, IdentityHashMap<Object, Object> visited) {
        if (o instanceof List) {
            List<Object> copy = new ArrayList<>(o.size());
            for (Object e : o) {
                copy.add(copy(e, visited));
            }
            return copy;
        }
        if (o instanceof Set) {
            Set<Object> copy = new LinkedHashSet<>();
            for (Object e : o) {
                copy.add(copy(e, visited));
            }
            return copy;
        }
        return o; // 其他集合类型（Queue 等）原样返回，较少出现在 DTO 中
    }

    private static Object copyMap(Map<?, ?> o, IdentityHashMap<Object, Object> visited) {
        Map<Object, Object> copy = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : o.entrySet()) {
            copy.put(copy(entry.getKey(), visited), copy(entry.getValue(), visited));
        }
        return copy;
    }

    private static boolean isResponseEntity(Class<?> type) {
        return "org.springframework.http.ResponseEntity".equals(type.getName());
    }

    /**
     * 反射深拷贝 ResponseEntity：取 body 深拷贝 + status（枚举，原样复用），
     * 通过 (Object, HttpStatus) 构造器重建。失败返回 null 交由默认路径回退。
     */
    private static Object copyResponseEntity(Object o, Class<?> type, IdentityHashMap<Object, Object> visited) {
        try {
            Method getBody = type.getMethod("getBody");
            Method getStatus = type.getMethod("getStatusCode");
            Object body = getBody.invoke(o);
            Object status = getStatus.invoke(o);
            Class<?> httpStatus = Class.forName("org.springframework.http.HttpStatus", false, type.getClassLoader());
            Constructor<?> ctor = type.getConstructor(Object.class, httpStatus);
            Object copyBody = copy(body, visited);
            Object copy = ctor.newInstance(copyBody, status);
            visited.put(o, copy);
            return copy;
        } catch (ReflectiveOperationException | LinkageError e) {
            log.warn("[DeepCopy] ResponseEntity 深拷贝失败, 回退默认逻辑: {}", e.getClass().getSimpleName());
            return null;
        }
    }

    private static Object serializeCopy(Object o) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(o);
        oos.close();
        ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
        ObjectInputStream ois = new ObjectInputStream(bis);
        Object copy = ois.readObject();
        ois.close();
        return copy;
    }

    private static Constructor<?> getNoArgConstructor(Class<?> type) {
        return CTOR_CACHE.computeIfAbsent(type, t -> {
            try {
                Constructor<?> ctor = t.getDeclaredConstructor();
                ctor.setAccessible(true);
                return ctor;
            } catch (NoSuchMethodException e) {
                return null;
            }
        });
    }

    private static void warnOnce(Class<?> type) {
        if (WARNED_TYPES.add(type)) {
            log.warn("[DeepCopy] 类型 {} 无法深拷贝（无无参构造器且不可序列化），将返回原始引用，"
                    + "@EncryptResult 出参加密可能影响原始对象，请为 DTO 提供无参构造器或实现 Serializable", type.getName());
        }
    }

    private static boolean isImmutableLeaf(Class<?> type) {
        return type.isPrimitive()
                || type.isEnum()
                || String.class.equals(type)
                || Boolean.class.equals(type)
                || Character.class.equals(type)
                || Class.class.equals(type)
                || Number.class.isAssignableFrom(type)
                || BigDecimal.class.equals(type)
                || BigInteger.class.equals(type)
                || UUID.class.equals(type)
                || Locale.class.equals(type)
                || type.getName().startsWith("java.time.");
    }

    private static boolean isJdkInternal(Class<?> type) {
        String name = type.getName();
        return name.startsWith("java.") || name.startsWith("javax.")
                || name.startsWith("jdk.") || name.startsWith("sun.");
    }
}