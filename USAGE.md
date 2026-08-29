# sensitive-encrypt-spring-starter · 使用说明

> 适用版本：**v1.1.1**　适用场景：**Spring / Spring Boot / Spring Cloud** 项目
>
> 本文档是面向<b>业务方 / 运维 / 安全评审</b>的实操手册：从依赖引入、密钥配置、注解使用，
> 到密钥轮换、存量数据迁移、故障排查与上线自查。
> 设计原理与决策依据见 [BLUEPRINT.md](./BLUEPRINT.md)，快速概览见 [README.md](./README.md)。

---

## 1. 环境要求

| 项 | 要求 | 说明 |
| --- | --- | --- |
| JDK | 17+（21 亦可） | 组件无模块限制（业务类处于未命名模块，反射不受影响） |
| Spring Framework | 5.3+ | 纯 Spring 方式接入 |
| Spring Boot | 2.7+ / 3.x | **引入即生效**（自动装配），无需注解 |
| Spring Cloud | 任意（匹配对应 Boot 版本） | 配置项自动接入配置中心 |
| MyBatis | 3.5+（可选） | 仅当需要**落库加密**时引入 |
| mybatis-spring | 2.1.x（可选） | 同上 |
| MyBatis-Plus | 3.x（可选） | 自动兼容（其 FactoryBean 继承自 SqlSessionFactoryBean） |

> 组件对 mybatis / mybatis-spring / spring-boot-autoconfigure 均为 **provided** 依赖：
> 不强制传递版本，由业务方自行管理，避免版本冲突。

---

## 2. 依赖引入

### 2.1 Maven

```xml
<dependency>
    <groupId>com.yuik</groupId>
    <artifactId>sensitive-encrypt-spring-starter</artifactId>
    <version>1.1.1</version>
</dependency>

<!-- 需要落库加密时（版本由业务方自行管理） -->
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

### 2.2 Gradle

```groovy
implementation 'com.yuik:sensitive-encrypt-spring-starter:1.1.1'
implementation 'org.mybatis:mybatis:3.5.16'        // 需要落库加密时
implementation 'org.mybatis:mybatis-spring:2.1.2'
```

### 2.3 版本兼容矩阵

| 业务框架 | 组件版本 | 接入方式 |
| --- | --- | --- |
| Spring Framework 5.3+ | 1.1.1 | @EnableSensitiveEncrypt |
| Spring Boot 2.7+ | 1.1.1 | 自动装配（零注解）或 @EnableSensitiveEncrypt |
| Spring Boot 3.x（Spring 6） | 1.1.1 | 自动装配（零注解）或 @EnableSensitiveEncrypt |
| Spring Boot < 2.7 | 1.1.1 | @EnableSensitiveEncrypt（无自动装配注解支持） |
| Spring Cloud（含 Nacos/Apollo/Config Server） | 1.1.1 | 与对应 Boot 版本一致，见 §3.3 |

---

## 3. 快速接入

### 3.1 Spring Boot（推荐，零配置）

引入依赖后**无需任何注解**，自动装配已完成全部 Bean 注册：

```java
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

在实体字段打注解即可生效：

```java
public class User {
    private Long id;

    @EncryptField(keyAlias = "db-phone")
    private String phone;
    // getter / setter……
}
```

> 可选：若业务方偏好显式风格，也可在配置类上加 @EnableSensitiveEncrypt ——
> 组件会通过配置类去重 + 条件回退，两种方式并存不会重复注册。

### 3.2 纯 Spring

```java
@Configuration
@EnableSensitiveEncrypt   // 强制开启 AOP + 自动注入 MyBatis 拦截器
public class AppConfig {
    // 业务方原有配置……
}
```

### 3.3 Spring Cloud

- **配置中心**：非密钥配置项（如占位符）直接写入配置中心，组件经 Environment 自动读取，无需 @RefreshScope：

```yaml
# Nacos / Apollo / Spring Cloud Config 中
sensitive:
  encrypt:
    decrypt-fail-placeholder: "***"
```

- **密钥**：**禁止**入配置中心（R1 红线），必须走环境变量 / KMS / HSM（见 §4）；
- **多实例轮换**：各实例独立轮询密钥版本（默认 5 分钟）。由于密文内嵌版本号、解密按版本取钥，
  轮换窗口内新旧实例互不影响，无读写中断。建议灰度节奏：**先发新密钥 → 确认全部实例就绪 → 再切换版本号**。

### 3.4 接入自检

启动日志中出现以下信息即表示接入成功：

```
[SensitiveEncrypt] KeyProvider 已就绪: EnvKeyProvider
[SensitiveEncrypt] 已向 SqlSessionFactoryBean 追加 MybatisEncryptInterceptor, bean=sqlSessionFactory, 拦截器总数=1
[SensitiveKey] 密钥刷新任务已启动, 周期=300s
```

也可在启动后检查容器 Bean：

```java
@Autowired
private SensitiveCryptoService sensitiveCryptoService; // 存在即接入成功
```

---

## 4. 密钥配置（安全红线 R1：零硬编码）

### 4.1 环境变量命名规范

密钥别名中的 `-` 会被规范化为 `_`（大写），例如别名 `db-phone`：

| 用途 | 环境变量 | 示例值 |
| --- | --- | --- |
| 当前密钥（Base64） | `SENSITIVE_KEY_DB_PHONE` | `aB3dEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijk=` |
| 当前版本（可选） | `SENSITIVE_KEY_VERSION_DB_PHONE` | `v1`（默认） |
| 历史密钥（轮换后） | `SENSITIVE_KEY_DB_PHONE_V1`、`_V2`... | 各版本密钥 Base64 |

> 除环境变量外，同名 **JVM 系统属性**（`-DSENSITIVE_KEY_DB_PHONE=...`）可作为回退来源
> （便于 CI / 测试注入），但不属于业务配置文件。

### 4.2 生成密钥（AES-256，32 字节）

```bash
openssl rand -base64 32
# 输出形如：aB3dEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijk=
export SENSITIVE_KEY_DB_PHONE="<上面输出的值>"
```

> 支持 16 / 24 / 32 字节（AES-128/192/256）。生产环境建议 KMS / HSM 托管，见 §4.4。

### 4.3 自定义 KeyProvider（对接 KMS / HSM）

默认 `EnvKeyProvider` 足够测试环境使用。生产环境推荐覆盖为 KMS 实现 ——
只需在 Spring 容器中**定义一个 KeyProvider Bean**（组件默认实现不作为 Bean 注册，不存在类型歧义）：

```java
@Bean
public KeyProvider kmsKeyProvider() {
    return new KeyProvider() {
        @Override
        public byte[] getKeyBytes(String keyAlias) {
            // 从阿里云 KMS / 自建 KMS / HSM 拉取当前密钥
            return kmsClient.getSecretBytes("sensitive/" + keyAlias);
        }
        @Override
        public String getCurrentKeyVersion(String keyAlias) {
            return kmsClient.getCurrentVersion("sensitive/" + keyAlias);
        }
    };
}
```

需要解密**历史版本**密文时，同时实现可选接口：

```java
@Bean
public KeyProvider kmsKeyProvider() {
    return new VersionedKeyProvider() {
        @Override public byte[] getKeyBytes(String keyAlias) { ... }
        @Override public String getCurrentKeyVersion(String keyAlias) { ... }
        @Override public byte[] getKeyBytes(String keyAlias, String keyVersion) {
            return kmsClient.getSecretBytesByVersion("sensitive/" + keyAlias, keyVersion);
        }
    };
}
```

> 注意：容器中只允许**一个** KeyProvider Bean，多于一个会启动报错（fail-fast）。

---

## 5. 注解使用说明

### 5.1 @EnableSensitiveEncrypt

- 作用：一键开启组件（导入核心配置 + 强制 @EnableAspectJAutoProxy + 自动注入 MyBatis 拦截器）；
- 位置：任意 @Configuration 类；
- Spring Boot 项目可省略（自动装配）。

### 5.2 @EncryptField（字段加密）

- 作用：标注实体 / DTO 中需要加解密的字段，落库加密、查询解密、API 出入参加解密均识别；
- **约束**：字段类型必须为 String；keyAlias 必须能解析到密钥。

```java
// ✅ 正确
@EncryptField(keyAlias = "db-phone")
private String phone;

// ❌ 错误：非 String 类型（组件会安全跳过，但不加密）
@EncryptField(keyAlias = "db-phone")
private Long phone;

// ❌ 错误：keyAlias 不存在（加密时抛错，解密时降级）
@EncryptField(keyAlias = "db-not-exists")
private String phone;
```

### 5.3 @EncryptResult（出参加密）

- 作用：Controller 方法返回值（含嵌套 DTO / List / Map）中 @EncryptField 字段加密后返回；
- **自动深拷贝**：加密作用于副本，原始业务对象（写日志、发 MQ 使用）不被污染；
- **支持 ResponseEntity<T> / HttpEntity**：直接返回 `ResponseEntity.ok(dto)` 时，body 同样深拷贝并加密。

```java
@EncryptResult
@GetMapping("/user")
public UserDTO getUser() {
    UserDTO dto = new UserDTO();
    dto.setPhone("13800138000");
    return dto; // 返回给调用方的 phone 已是密文，业务对象 dto.phone 仍为明文
}

@EncryptResult
@GetMapping("/user-resp")
public ResponseEntity<UserDTO> getUserResponseEntity() {
    return ResponseEntity.ok(buildDto()); // body 自动深拷贝 + 加密，原始 DTO 不受影响
}
```

### 5.4 @DecryptParam（入参解密）

- 作用：Controller 方法参数对象（如 @RequestBody）中的 @EncryptField 字段在进入业务逻辑前解密；
- **非侵入**：组件解密的是参数的<b>深拷贝副本</b>，业务方法收到解密后的副本，
  <b>原始入参对象保持原样</b>（如 Jackson 反序列化的请求体不会被就地修改）。

```java
@PostMapping("/save")
public Result save(@RequestBody @DecryptParam UserDTO user) {
    // 此处 user.getPhone() 已是明文（解密副本，原始入参未被修改）
    return Result.success();
}
```

### 5.5 编程式调用（非注解场景）

```java
@Autowired
private SensitiveCryptoService cryptoService;

public String encryptPhone(String phone) {
    return cryptoService.encryptField(phone, "db-phone", "phone");
}

public String decryptPhone(String cipher) {
    // 结构上不是密文的值（脏明文 / 已解密值）原样返回；密文解密失败降级为占位符（默认 ***）
    return cryptoService.decryptField(cipher, "db-phone", "phone");
}
```

### 5.6 已知限制与边界（请务必阅读）

| 限制 | 说明与建议 |
| --- | --- |
| 按加密字段直接 SQL 查询 | `WHERE phone = ?` 传明文无法命中密文；建议加密索引或确定性加密扩展（v2 规划） |
| @EncryptField 仅支持 String | 非 String 字段被安全跳过（不加密、不抛异常） |
| resultType="map" / 集合值（List<String> 等） | 不参与加解密（缺少 keyAlias 上下文）；敏感字段请使用 POJO 实体映射 |
| 注解仅对 public 方法生效 | Spring AOP 默认限制；非 public 方法上的 @EncryptResult / @DecryptParam 静默不生效 |
| 深拷贝依赖无参构造器 | 不可拷贝类型（无无参构造且不可序列化）回退共享引用并打 WARN；DTO 请提供无参构造器或实现 Serializable |
| Cursor 流式查询 | 已支持（v1.1.1+）：游标元素懒解密 |
| ResponseEntity / HttpEntity | 已支持（v1.1.1+）：body 深拷贝后加密 |

---

## 6. 配置项参考（非密钥类）

| 配置项 | 默认值 | 说明 | 读取方式 |
| --- | --- | --- | --- |
| `sensitive.encrypt.decrypt-fail-placeholder` | `***` | 解密失败（篡改 / 脏数据 / 密钥缺失）返回的脱敏占位符 | Environment（yml / 配置中心 / 系统属性） |

```yaml
sensitive:
  encrypt:
    decrypt-fail-placeholder: "******"
```

> ⚠️ 该配置项仅用于**非密钥**类占位符；密钥类配置（`SENSITIVE_KEY_*`）禁止写入任何配置文件。

---

## 7. 密钥轮换操作手册（无感轮换）

前置：组件每 5 分钟检测一次密钥版本变化（首次 60s 后），历史密钥自动归档（保留最近 10 个版本）。

```bash
# 第 1 步：生成新密钥并发布到所有实例
openssl rand -base64 32
export SENSITIVE_KEY_DB_PHONE="<新密钥>"        # 所有实例环境变量（或 KMS 更新密钥）

# 第 2 步：确认全部实例就绪后，切换版本号
export SENSITIVE_KEY_VERSION_DB_PHONE="v2"

# 第 3 步（可选）：显式配置历史密钥（EnvKeyProvider 场景）
export SENSITIVE_KEY_DB_PHONE_V1="<旧密钥>"
```

轮换后：

- 新写入数据用 v2 加密，密文内嵌版本 `v2`；
- 历史数据仍携带 `v1`，解密时自动取归档密钥，**旧数据零迁移**；
- 全部数据完成重写后可清理 `SENSITIVE_KEY_DB_PHONE_V1` 等历史密钥。

> 排障提示：若轮换后出现「解密失败」WARN 且密文摘要 tail 对应的数据是轮换前写入的，
> 请检查历史密钥是否已配置（`SENSITIVE_KEY_{ALIAS}_{VERSION}`）或 KMS 是否支持按版本取钥。

---

## 8. 存量数据迁移（明文 → 密文）

组件**不支持**直接读取存量明文（解密失败会降级为占位符），迁移必须主动加密落库。推荐两种方式：

### 方式 A：批量脚本重写（当前可用）

利用组件的透明加密，编写一次性迁移任务：按主键分批读出实体，再原样写回
（ParameterHandler 自动加密；写回实体携带的是明文，不会双重加密）：

```java
// 伪代码：分批迁移
long cursor = 0;
while (true) {
    List<User> batch = userMapper.selectPage(cursor, 1000); // 按主键分批
    if (batch.isEmpty()) break;
    for (User u : batch) {
        // u.getPhone() 为存量明文；直接 update 触发透明加密
        userMapper.updateById(u);
    }
    cursor = batch.get(batch.size() - 1).getId();
}
```

> 迁移期间建议：先在小流量库验证、记录迁移前后行数、保留旧表备份。

### 方式 B：只解密 / 灰度模式（组件 v1.x 规划）

计划提供「只解密模式」开关，用于灰度期让部分实例只读存量数据不写入新密文；落地前请使用方式 A。

---

## 9. 日志解读与故障排查

### 9.1 正常日志

```
[SensitiveEncrypt] KeyProvider 已就绪: EnvKeyProvider
[SensitiveEncrypt] 已向 SqlSessionFactoryBean 追加 MybatisEncryptInterceptor, bean=sqlSessionFactory, 拦截器总数=1
[SensitiveKey] 密钥刷新任务已启动, 周期=300s
[SensitiveKey] 密钥无感轮换完成 alias=db-phone, v1 -> v2
```

### 9.2 解密降级（预期内的容错，关注频次）

```
WARN [SensitiveDecrypt] 字段 phone 解密失败, 异常类型=DecryptionException, 密文摘要=len=64,tail=xxxx, 已降级返回占位符
```

高频出现时的排查顺序：

1. 密文是否为**轮换前**写入且历史密钥缺失（补配 `SENSITIVE_KEY_{ALIAS}_{VERSION}`）；
2. 是否存在**存量明文**脏数据（走 §8 迁移）；
3. 是否数据被篡改（异常类型含 `AEADBadTagException` 时重点排查）。

### 9.3 启动失败（fail-fast）

| 报错 | 原因 | 处理 |
| --- | --- | --- |
| `未配置密钥: 环境变量/系统属性 [SENSITIVE_KEY_XXX] 不存在` | 密钥未配置 | 配置环境变量或 KMS KeyProvider |
| `检测到多个 KeyProvider Bean（N 个）` | 定义了多个 KeyProvider | 保留一个，删除多余 Bean |
| `注入 MybatisEncryptInterceptor 失败` | SqlSessionFactoryBean 反射注入异常 | 检查 mybatis-spring 版本（2.1.x） |
| `密钥长度不合法 ... AES 要求 16/24/32 字节` | Base64 解码后长度不对 | 用 `openssl rand -base64 16/24/32` 重新生成 |

---

## 10. 上线前安全自查清单（Checklist）

- [ ] 代码与配置文件中**无**任何明文密钥（grep `SENSITIVE_KEY_`、`secret`、`key=`）；
- [ ] 生产密钥由 KMS / HSM 托管或环境变量注入，未提交版本库；
- [ ] 所有敏感字段（手机号 / 身份证 / 银行卡等）均已标注 @EncryptField 且 keyAlias 正确；
- [ ] 非 String 敏感字段已确认跳过策略或已完成类型改造；
- [ ] 日志脱敏规则生效（无明文 / 完整密文入日志）；
- [ ] 密钥轮换演练通过（§7），历史密钥可解密旧数据；
- [ ] 存量数据迁移已完成或已排期（§8）；
- [ ] 解密降级 WARN 已接入监控告警；
- [ ] 多实例部署环境已完成轮换灰度验证（§3.3）。

---

## 11. 性能与容量建议

| 关注点 | 建议 |
| --- | --- |
| 字段元数据 | 组件已缓存（FieldMetaCache），热路径无反射，无需业务优化 |
| 批量查询 | ResultSetHandler 对 List 结果集批量解密，已内置 |
| 密文长度 | GCM 密文比明文长约 45~60 字符（版本+IV+Tag+Base64 膨胀），请评估列宽（建议 VARCHAR 512+）与索引影响 |
| 加密开销 | 单次 AES-GCM 开销微秒级；批量场景可忽略 |
| 密钥拉取 | 组件缓存密钥并定时刷新（5 分钟），不会在热路径频繁访问 KMS |
| 缓存容量 | 历史密钥默认保留 10 个版本，超出自动擦除 |