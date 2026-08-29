# sensitive-encrypt-spring-starter

企业级「敏感数据透明加解密」组件 —— **Spring / Spring Boot / Spring Cloud 三端无缝接入**。

> 📚 **文档导航**
> - 📖 [USAGE.md](./USAGE.md) —— **使用说明**：三端接入、密钥配置、注解使用、密钥轮换、存量迁移、排障与上线自查清单
> - 📐 [BLUEPRINT.md](./BLUEPRINT.md) —— 设计蓝图：架构、安全决策、关键流程、演进路线

业务方引入 jar 包后，在实体字段 / Controller 方法上打注解，即可获得 **数据库落库加密** 与 **API 传输加密** 的透明能力：

- **纯 Spring**：配置类加 `@EnableSensitiveEncrypt`；
- **Spring Boot（2.7+ / 3.x）**：**引入依赖即生效**，无需任何注解；
- **Spring Cloud**：配置项自动接入配置中心（Nacos / Apollo / Config Server），密钥仍走环境变量 / KMS / HSM。

> ⚠️ 安全红线（组件强制约束）：
> - 密钥**零硬编码**：任何 Java 代码 / properties / yml 中禁止出现明文密钥，密钥一律通过 KeyProvider SPI 获取（环境变量 / KMS / HSM）。
> - 对称加密**仅允许 AES/GCM/NoPadding**（AEAD），禁止 ECB / CBC / DES / 3DES；IV 每次随机生成（12 字节）并与密文拼接存储。
> - 密钥使用 byte[] 接收，Cipher 初始化并完成加解密后**立即 Arrays.fill 擦除**，防止密钥驻留 JVM 堆被 Dump。
> - 日志**只允许**打印字段名、数据长度、脱敏摘要，禁止打印明文、密钥、完整密文。

---

## 1. 快速开始

### 1.1 引入依赖

```xml
<dependency>
    <groupId>com.yuik</groupId>
    <artifactId>sensitive-encrypt-spring-starter</artifactId>
    <version>1.1.1</version>
</dependency>
<!-- 业务方自行管理版本： -->
<dependency>
    <groupId>org.mybatis</groupId>
    <artifactId>mybatis</artifactId>
    <version>3.5.x</version>
</dependency>
<dependency>
    <groupId>org.mybatis</groupId>
    <artifactId>mybatis-spring</artifactId>
    <version>2.1.x</version>
</dependency>
```

> 组件对 mybatis / mybatis-spring 为 **provided** 依赖，不强制传递，避免版本冲突。
> 支持 MyBatis-Plus（MybatisSqlSessionFactoryBean 继承自 SqlSessionFactoryBean，自动兼容）。

### 1.2 Spring Boot / Spring Cloud 无缝接入

**Spring Boot（推荐，零配置）**：引入依赖即自动装配完毕（`spring.factories` + `AutoConfiguration.imports` 双通道注册），
**无需**添加任何注解：

```java
// ✅ Spring Boot 项目：什么都不用加，jar 引入即生效
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

- Boot 2.7+ / Boot 3.x 均支持（组件无 jakarta 依赖，Spring 6 下同样可用）；
- 配置项通过 Environment 读取，支持 application.yml 与**配置中心**（Nacos / Apollo / Spring Cloud Config）：

```yaml
sensitive:
  encrypt:
    decrypt-fail-placeholder: "***"   # 非密钥类配置（密钥禁止写配置文件）
```

- 业务方若偏好显式风格，也可同时使用 `@EnableSensitiveEncrypt`：Spring 会对同一配置类去重，
  自动装配自动回退（`@ConditionalOnMissingBean`），两种方式并存不会重复注册；
- MyBatis / MyBatis-Plus 的 Boot Starter 自动创建的 `SqlSessionFactoryBean` 同样会被
  `BeanPostProcessor` 无侵入注入拦截器，无需任何额外配置。

**Spring Cloud 注意点**：
- 多实例部署时，每实例独立轮询密钥版本（默认 5 分钟）；轮换瞬间存在短暂版本不一致窗口，
  由于密文内嵌版本号、解密按版本取钥，旧实例仍可解密新密文的旧版本，反之亦然，**无读写中断**；
- 密钥版本切换建议遵循「先发新密钥、确认实例就绪、再切版本」的灰度节奏。

### 1.3 纯 Spring 开启组件

```java
@Configuration
@EnableSensitiveEncrypt   // 内部已强制 @EnableAspectJAutoProxy + @Import(SensitiveEncryptConfiguration)
public class AppConfig {
    // 业务方原有配置……
}
```

### 1.4 配置密钥（环境变量，禁止写入配置文件）

```bash
# 密钥以 Base64 编码放在环境变量中，变量名为 SENSITIVE_KEY_ + 别名（大写，- 转 _）
export SENSITIVE_KEY_DB_PHONE="<Base64 编码的 16/24/32 字节 AES 密钥>"
# 可选：当前密钥版本（默认 v1）；轮换时改为 v2 并配置新密钥
export SENSITIVE_KEY_VERSION_DB_PHONE="v1"
# 可选：历史密钥（轮换后旧数据解密需要）
export SENSITIVE_KEY_DB_PHONE_V1="<旧密钥 Base64>"
```

- 别名中的 - 会被规范化为 _（POSIX 环境变量名不允许 -），如 db-phone → SENSITIVE_KEY_DB_PHONE。
- 除环境变量外，同名的 **JVM 系统属性**（-DSENSITIVE_KEY_DB_PHONE=...）也可作为回退来源（便于 CI / 测试，非配置文件）。

### 1.5 实体字段加密（落库 + 查询透明加解密）

```java
public class User {
    private Long id;
    private String name;

    @EncryptField(keyAlias = "db-phone")   // ✅ 仅支持 String 字段
    private String phone;
    // getter / setter……
}
```

组件通过 BeanPostProcessor **无侵入**地把 MybatisEncryptInterceptor 追加到 SqlSessionFactoryBean.plugins 末尾：
- ParameterHandler：insert/update 时自动加密实体字段；
- ResultSetHandler：查询结果（含 List 批量结果）自动解密。

### 1.6 API 出入参加解密

```java
@RestController
public class UserController {

    // ✅ 出参加密：组件深拷贝返回值后加密，不影响原始业务对象
    @EncryptResult
    @GetMapping("/user")
    public UserDTO getUser() { ... }

    // ✅ 入参解密（非侵入）：请求体中的 @EncryptField 字段自动解密，
    //    业务方法收到解密副本，原始入参对象不被修改
    @PostMapping("/save")
    public Result save(@RequestBody @DecryptParam UserDTO user) { ... }
}
```

---

## 2. 架构总览

```
业务代码
   │  @EnableSensitiveEncrypt → @Import(SensitiveEncryptConfiguration)
   ▼
SensitiveEncryptConfiguration（@EnableAspectJAutoProxy）
   ├── CachedKeyManager（密钥缓存 + 5 分钟定时刷新，支持无感轮换）
   │        └── KeyProvider SPI（默认 EnvKeyProvider，业务可覆盖为 KMS/HSM）
   ├── EncryptorFactory → AesGcmEncryptor（AES/GCM/NoPadding，IV 随机，内存擦除）
   ├── FieldMetaCache（ConcurrentHashMap 缓存字段元数据，禁止实时反射）
   ├── SensitiveCryptoService（统一加解密 + 异常降级 + 日志脱敏）
   ├── SqlSessionFactoryBeanPostProcessor（反射追加 MyBatis 拦截器，无侵入）
   └── SensitiveApiAspect（@EncryptResult 深拷贝出参加密 / @DecryptParam 入参解密）
```

### 2.1 密文结构（Base64 编码前）

```
[1 字节:版本长度 N] + [N 字节:版本字符串 UTF-8] + [12 字节:随机 IV] + [密文 + 16 字节 GCM Tag]
```

版本信息内嵌于密文，**密钥轮换后旧密文仍可按版本号取到旧密钥解密**。

### 2.2 密钥轮换（无感）

1. 生成新密钥，Base64 编码后更新环境变量 SENSITIVE_KEY_DB_PHONE，并把 SENSITIVE_KEY_VERSION_DB_PHONE 改为 v2；
2. 组件每 5 分钟刷新一次：检测到版本变化后加载新密钥为当前密钥，旧密钥自动归档（保留最近 10 个版本）；
3. 新写入的数据用 v2 加密，历史数据仍用 v1 解密；全部迁移完成后可清理历史密钥。

---

## 3. 自定义 KeyProvider（对接 KMS / HSM）

组件默认使用 EnvKeyProvider。业务方只需在 Spring 容器中**定义一个 KeyProvider Bean** 即完成覆盖
（组件不会注册默认 Bean，因此不存在类型歧义；多于一个 KeyProvider Bean 会启动报错）。

```java
@Bean
public KeyProvider kmsKeyProvider() {
    return new KeyProvider() {
        @Override
        public byte[] getKeyBytes(String keyAlias) {
            // 从阿里云 KMS / 自建 KMS / HSM 拉取当前密钥（返回 byte[]，调用方负责擦除）
            return kmsClient.getSecretBytes("sensitive/" + keyAlias);
        }
        @Override
        public String getCurrentKeyVersion(String keyAlias) {
            return kmsClient.getCurrentVersion("sensitive/" + keyAlias);
        }
    };
}
```

需要解密历史版本数据时，同时实现可选接口 VersionedKeyProvider：

```java
@Bean
public KeyProvider kmsKeyProvider() {
    return new VersionedKeyProvider() {
        @Override public byte[] getKeyBytes(String keyAlias) { ... }
        @Override public String getCurrentKeyVersion(String keyAlias) { ... }
        @Override public byte[] getKeyBytes(String keyAlias, String keyVersion) { /* 按版本取历史密钥 */ }
    };
}
```

---

## 4. 可配置项（非密钥类配置，通过 Spring Environment 读取）

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| sensitive.encrypt.decrypt-fail-placeholder | *** | 解密失败（脏数据 / 篡改 / 密钥缺失）时返回的脱敏占位符 |

示例：-Dsensitive.encrypt.decrypt-fail-placeholder="******"

---

## 5. 已知限制（设计取舍，请知悉）

1. **暂不支持按加密字段直接 SQL 查询**（如 WHERE phone = ? 传入明文）：phone 落库后为密文，明文条件无法命中。
   建议：加密索引 / 先解密再内存过滤 / 使用确定性加密扩展（需自行评估安全风险）。
2. **@EncryptField 仅支持 String 类型字段**，非 String 字段会被跳过（见类注释）。
3. **resultType="map" 与集合值（如 List<String>）不参与加解密**：字段元数据来自实体类注解，Map/标量集合缺少 keyAlias 上下文；
   请使用实体映射（POJO resultType）承载敏感字段。
4. **注解仅对 public 方法生效**（Spring AOP 默认限制），非 public 方法上的 @EncryptResult / @DecryptParam 静默不生效。
5. 出参深拷贝依赖目标类型具有**无参构造器**；否则退化为序列化拷贝，再不行则原样返回并打 WARN
   （@EncryptResult 返回 ResponseEntity<T> 已内置深拷贝支持）。
6. 解密失败默认返回 *** 占位符（可配置）；**结构上不是密文的值**（脏明文 / 已解密值）按"返回原值"语义原样返回，
   不会破坏数据。

---

## 6. 常见问题（FAQ）

### Q1：为什么禁止把密钥写进 yml？
配置文件会进入版本库 / 备份 / 日志采集，一旦泄露即等于密钥泄露，无法满足等保三级「密钥管理」与 GDPR「数据保护」要求。
安全替代：测试环境使用 **Mock KeyProvider**（从测试专用的环境变量读取），生产使用 KMS/HSM。

### Q2：为什么禁用 ECB / CBC？
- ECB：相同明文产生相同密文，可被频率分析破解，明文模式直接泄露；
- CBC：无完整性校验，存在 padding oracle 攻击面。
AES/GCM/NoPadding 为 AEAD 模式，一次完成**机密性 + 完整性（GCM Tag）**，篡改可被 AEADBadTagException 检出。

### Q3：密钥在 JVM 堆中会驻留吗？
组件在 Cipher.init 完成后立即 Arrays.fill(keyBytes, 0) 擦除**所有临时密钥拷贝**。
CachedKeyManager 中保留的「主拷贝」是轮换解密所必需的，且对外只交付防御性拷贝；
刷新 / 销毁时同样执行内存擦除，尽可能压缩密钥在堆中的驻留窗口。

### Q4：解密失败会不会导致接口 500？
不会。SensitiveCryptoService.decryptField 捕获**所有异常**（含 AEADBadTagException、脏数据 IllegalArgumentException、
历史密钥缺失等），记录 WARN（仅字段名 + 异常类型 + 密文摘要），返回占位符，保证高可用。
结构上不是本组件密文的值（如历史明文脏数据）会按"返回原值"语义原样返回，不破坏数据。

### Q5：写库后业务实体字段会变成密文吗？
不会（v1.1.1+）。MyBatis 写库采用**加密-绑定-恢复**：拦截器在参数绑定前加密、绑定完成后立即恢复业务实体为明文，
业务后续写日志 / 发 MQ / 直接返回实体拿到的都是明文。

### Q6：@EncryptResult 返回 ResponseEntity<T> 或使用 Cursor 流式查询会怎样？
已支持（v1.1.1+）：ResponseEntity 的 body 会深拷贝后加密（原始对象不受影响）；Cursor 流式查询结果逐元素懒解密。