package com.yuik.sensitive.mybatis;

import com.yuik.sensitive.service.SensitiveCryptoService;
import org.apache.ibatis.cursor.Cursor;
import org.apache.ibatis.executor.parameter.ParameterHandler;
import org.apache.ibatis.executor.resultset.ResultSetHandler;
import org.apache.ibatis.plugin.Interceptor;
import org.apache.ibatis.plugin.Intercepts;
import org.apache.ibatis.plugin.Invocation;
import org.apache.ibatis.plugin.Plugin;
import org.apache.ibatis.plugin.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

/**
 * MyBatis 加解密拦截器。
 *
 * <p>拦截点：
 * <ul>
 *     <li>{@link ParameterHandler#setParameters}：写库前加密实体中 @EncryptField 字段
 *         （加密-绑定-恢复，业务实体保持明文，见 {@link #encryptParameters}）；</li>
 *     <li>{@link ResultSetHandler#handleResultSets}：查询后解密结果（含 List 批量解密）；</li>
 *     <li>{@link ResultSetHandler#handleCursorResultSets}：流式 Cursor 查询懒解密
 *         （M1 修复，防止游标元素以密文暴露给业务）。</li>
 * </ul>
 *
 * <p>// DESIGN-NOTE: 无侵入注入 —— 本拦截器不要求业务方手动配置，
 * 由 {@link SqlSessionFactoryBeanPostProcessor} 通过反射追加到
 * SqlSessionFactoryBean 的 plugins 数组末尾（兼容 MyBatis-Plus）。
 *
 * @author sensitive-encrypt-spring-starter
 */
@Intercepts({
        @Signature(type = ResultSetHandler.class, method = "handleResultSets", args = {Statement.class}),
        @Signature(type = ResultSetHandler.class, method = "handleCursorResultSets", args = {Statement.class}),
        @Signature(type = ParameterHandler.class, method = "setParameters", args = {PreparedStatement.class})
})
public class MybatisEncryptInterceptor implements Interceptor {

    private static final Logger log = LoggerFactory.getLogger(MybatisEncryptInterceptor.class);

    private SensitiveCryptoService cryptoService;

    /** 由 SqlSessionFactoryBeanPostProcessor 注入。 */
    public void setCryptoService(SensitiveCryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        Object target = invocation.getTarget();
        if (target instanceof ParameterHandler) {
            Object parameterObject = ((ParameterHandler) target).getParameterObject();
            SensitiveCryptoService.FieldSnapshot snapshot = encryptParameters(parameterObject);
            try {
                return invocation.proceed();
            } finally {
                // DESIGN-NOTE: 加密-绑定-恢复 —— proceed 完成参数绑定后立即恢复业务实体原始值，
                // 避免 insert/update 后业务对象字段变成密文（M3 修复，与 AOP 深拷贝隔离同一目标）
                cryptoService.restoreFields(snapshot);
            }
        }
        if (target instanceof ResultSetHandler) {
            Object result = invocation.proceed();
            if (result instanceof Cursor) {
                // M1 修复：流式游标结果懒解密
                return new DecryptingCursor<>((Cursor<?>) result, cryptoService);
            }
            decryptResults(result);
            return result;
        }
        return invocation.proceed();
    }

    /**
     * 写库前加密参数对象中的 @EncryptField 字段，并返回原值快照。
     * 支持：单实体 / @Param Map（值为实体）/ List 批量 / 数组 / null。
     */
    private SensitiveCryptoService.FieldSnapshot encryptParameters(Object parameter) {
        if (parameter == null) {
            return null;
        }
        // DESIGN-NOTE: fail-closed —— 加密服务缺失时禁止静默明文落库，宁可写库失败
        if (cryptoService == null) {
            throw new IllegalStateException("SensitiveCryptoService 未注入 MybatisEncryptInterceptor，"
                    + "拒绝以明文执行写库（请检查组件配置）");
        }
        try {
            return cryptoService.encryptObjectFieldsWithSnapshot(parameter);
        } catch (Exception e) {
            // 加密失败必须阻止写库（密文一致性优先），但日志只打类型与异常摘要
            throw new IllegalStateException("MyBatis 写库前加密失败: " + e.getMessage(), e);
        }
    }

    /**
     * 查询后解密结果集中的 @EncryptField 字段。
     *
     * <p>// DESIGN-NOTE: 批量解密 —— List 结果集一次性遍历解密，字段元数据走缓存，
     * 避免逐条反射的性能损耗。
     */
    private void decryptResults(Object result) {
        if (result == null || cryptoService == null) {
            return;
        }
        try {
            if (result instanceof List) {
                for (Object item : (List<?>) result) {
                    if (item != null) {
                        cryptoService.decryptObjectFields(item);
                    }
                }
                return;
            }
            if (result instanceof Iterable) {
                for (Object item : (Iterable<?>) result) {
                    if (item != null) {
                        cryptoService.decryptObjectFields(item);
                    }
                }
                return;
            }
            cryptoService.decryptObjectFields(result);
        } catch (Exception e) {
            // 解密失败已由 SensitiveCryptoService 统一降级，这里仅兜底记录
            log.warn("[MybatisEncrypt] 结果解密异常: {}", e.getClass().getSimpleName());
        }
    }

    @Override
    public Object plugin(Object target) {
        return Plugin.wrap(target, this);
    }

    @Override
    public void setProperties(Properties properties) {
        // 无外部配置属性
    }

    /**
     * 懒解密游标包装器：遍历元素时逐个解密，避免一次性加载全量数据。
     */
    static final class DecryptingCursor<T> implements Cursor<T> {

        private final Cursor<T> delegate;
        private final SensitiveCryptoService cryptoService;

        DecryptingCursor(Cursor<?> delegate, SensitiveCryptoService cryptoService) {
            this.delegate = (Cursor<T>) delegate;
            this.cryptoService = cryptoService;
        }

        @Override
        public Iterator<T> iterator() {
            final Iterator<T> it = delegate.iterator();
            return new Iterator<T>() {
                @Override
                public boolean hasNext() {
                    return it.hasNext();
                }

                @Override
                public T next() {
                    T value = it.next();
                    if (value != null && cryptoService != null) {
                        cryptoService.decryptObjectFields(value);
                    }
                    return value;
                }

                @Override
                public void remove() {
                    it.remove();
                }
            };
        }

        @Override
        public boolean isOpen() {
            return delegate.isOpen();
        }

        @Override
        public boolean isConsumed() {
            return delegate.isConsumed();
        }

        @Override
        public int getCurrentIndex() {
            return delegate.getCurrentIndex();
        }

        @Override
        public void close() throws IOException {
            // DESIGN-NOTE: MyBatis 的 Cursor 接口未重声明 close()（仅继承 Closeable），
            // 因此 delegate.close() 声明了受检异常 IOException —— 必须向上声明，
            // 否则编译报 "unreported exception IOException"。
            // 业务侧 try-with-resources（Closeable 语义）可正常使用，无需额外处理。
            delegate.close();
        }
    }
}
