package com.yuik.sensitive.aspect;

import com.yuik.sensitive.annotation.DecryptParam;
import com.yuik.sensitive.annotation.EncryptResult;
import com.yuik.sensitive.service.SensitiveCryptoService;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.BridgeMethodResolver;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.concurrent.ConcurrentHashMap;

/**
 * API 出入加解密切面。
 *
 * <p>两个切点：
 * <ul>
 *     <li><b>@EncryptResult</b>（出参加密）：方法返回后<b>深拷贝</b>返回值，在副本上递归加密
 *         @EncryptField 字段后返回副本 —— 原始业务对象不被污染；</li>
 *     <li><b>Controller 方法 + @DecryptParam 参数</b>（入参解密，非侵入）：调用前对参数
 *         深拷贝副本解密，并通过 {@code proceed(newArgs)} 替换方法实参——原始入参对象零修改。</li>
 * </ul>
 *
 * <p>// DESIGN-NOTE: 深拷贝隔离 —— 若直接加密原始返回值，同一请求链路中后续逻辑
 * （写日志、发 MQ）拿到的将是密文，引发隐蔽 Bug；深拷贝保证业务对象始终是明文。
 *
 * @author sensitive-encrypt-spring-starter
 */
@Aspect
public class SensitiveApiAspect {

    private static final Logger log = LoggerFactory.getLogger(SensitiveApiAspect.class);

    private final SensitiveCryptoService cryptoService;

    /** Method -> 是否含 @DecryptParam 参数的缓存（避免每次请求重复反射方法签名）。 */
    private final ConcurrentHashMap<Method, Boolean> decryptParamMethodCache = new ConcurrentHashMap<>();

    public SensitiveApiAspect(SensitiveCryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @Pointcut("@annotation(com.yuik.sensitive.annotation.EncryptResult)")
    public void encryptResultPointcut() {
    }

    @Pointcut("@within(org.springframework.stereotype.Controller) || @within(org.springframework.web.bind.annotation.RestController)")
    public void controllerPointcut() {
    }

    /** 出参加密：深拷贝 + 递归加密。 */
    @Around("encryptResultPointcut()")
    public Object handleEncryptResult(ProceedingJoinPoint pjp) throws Throwable {
        Object result = pjp.proceed();
        if (result == null) {
            return null;
        }
        return cryptoService.deepCopyAndEncrypt(result);
    }

    /**
     * 入参解密（非侵入）：Controller 方法中带 @DecryptParam 的参数对象在调用前<b>副本解密</b>。
     *
     * <p>// DESIGN-NOTE: 非侵入原则 —— 业务入参对象（如 Jackson 反序列化的请求体）<b>不被修改</b>：
     * 解密作用于深拷贝副本，通过 {@code proceed(newArgs)} 将解密后的副本替换为方法实参，
     * 业务方法内拿到的是明文副本，原始入参保持原样。
     */
    @Around("controllerPointcut()")
    public Object handleDecryptParam(ProceedingJoinPoint pjp) throws Throwable {
        Method method = resolveMethod(pjp);
        if (method != null && hasDecryptParam(method)) {
            Object[] args = pjp.getArgs();
            Annotation[][] parameterAnnotations = method.getParameterAnnotations();
            Object[] newArgs = null;
            for (int i = 0; i < parameterAnnotations.length && i < args.length; i++) {
                if (contains(parameterAnnotations[i], DecryptParam.class) && args[i] != null) {
                    if (newArgs == null) {
                        newArgs = args.clone();
                    }
                    newArgs[i] = cryptoService.deepCopyAndDecrypt(args[i]);
                }
            }
            if (newArgs != null) {
                return pjp.proceed(newArgs);
            }
        }
        return pjp.proceed();
    }

    private Method resolveMethod(ProceedingJoinPoint pjp) {
        if (pjp.getSignature() instanceof MethodSignature) {
            Method method = ((MethodSignature) pjp.getSignature()).getMethod();
            // 桥接方法（泛型擦除）解析到真实方法，保证参数注解可见
            return BridgeMethodResolver.findBridgedMethod(method);
        }
        return null;
    }

    private boolean hasDecryptParam(Method method) {
        return decryptParamMethodCache.computeIfAbsent(method, m -> {
            for (Annotation[] annotations : m.getParameterAnnotations()) {
                if (contains(annotations, DecryptParam.class)) {
                    return Boolean.TRUE;
                }
            }
            return Boolean.FALSE;
        });
    }

    private static boolean contains(Annotation[] annotations, Class<? extends Annotation> type) {
        for (Annotation a : annotations) {
            if (a.annotationType() == type) {
                return true;
            }
        }
        return false;
    }
}