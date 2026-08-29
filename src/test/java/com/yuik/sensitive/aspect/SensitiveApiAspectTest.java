package com.yuik.sensitive.aspect;

import com.yuik.sensitive.TestKeys;
import com.yuik.sensitive.annotation.DecryptParam;
import com.yuik.sensitive.annotation.EnableSensitiveEncrypt;
import com.yuik.sensitive.annotation.EncryptField;
import com.yuik.sensitive.annotation.EncryptResult;
import com.yuik.sensitive.crypto.CiphertextCodec;
import com.yuik.sensitive.crypto.EncryptorFactory;
import com.yuik.sensitive.key.CachedKeyManager;
import com.yuik.sensitive.key.EnvKeyProvider;
import com.yuik.sensitive.metadata.FieldMetaCache;
import com.yuik.sensitive.service.SensitiveCryptoService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * API 切面测试：验证 @EncryptResult 深拷贝隔离与 @DecryptParam 入参解密。
 */
class SensitiveApiAspectTest {

    public static class UserDTO {
        private String name;

        @EncryptField(keyAlias = "api-phone")
        private String phone;

        private List<UserDTO> friends;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getPhone() {
            return phone;
        }

        public void setPhone(String phone) {
            this.phone = phone;
        }

        public List<UserDTO> getFriends() {
            return friends;
        }

        public void setFriends(List<UserDTO> friends) {
            this.friends = friends;
        }
    }

    @RestController
    public static class SampleController {
        static volatile UserDTO lastReturned;
        static volatile UserDTO lastResponseEntityBody;

        @EncryptResult
        @GetMapping("/user")
        public UserDTO getUser() {
            UserDTO dto = new UserDTO();
            dto.setName("Alice");
            dto.setPhone("13800138000");
            UserDTO friend = new UserDTO();
            friend.setName("Bob");
            friend.setPhone("13900000000");
            dto.setFriends(new ArrayList<>(Arrays.asList(friend)));
            lastReturned = dto;
            return dto;
        }

        /** H1 修复验证：@EncryptResult 返回 ResponseEntity<T> 时 body 必须加密且不污染原始对象。 */
        @EncryptResult
        @GetMapping("/user-resp")
        public org.springframework.http.ResponseEntity<UserDTO> getUserResponseEntity() {
            UserDTO dto = new UserDTO();
            dto.setName("Resp");
            dto.setPhone("13711112222");
            lastResponseEntityBody = dto;
            return org.springframework.http.ResponseEntity.ok(dto);
        }

        @PostMapping("/save")
        public String save(@RequestBody @DecryptParam UserDTO dto) {
            return dto.getPhone(); // 返回解密后的值供测试断言
        }

        @GetMapping("/plain")
        public String plain() {
            return "no-encrypt";
        }

        /** 无 @DecryptParam 的入参方法：即使传入密文也不应解密。 */
        @PostMapping("/echo")
        public String echo(@RequestBody UserDTO dto) {
            return dto.getPhone();
        }
    }

    @Configuration
    @EnableSensitiveEncrypt
    static class TestWebConfig {
        @Bean
        public SampleController sampleController() {
            return new SampleController();
        }
    }

    private AnnotationConfigApplicationContext context;

    @BeforeEach
    void setUp() {
        TestKeys.installEnvKey(TestKeys.API_ALIAS, TestKeys.KEY_B64_OTHER);
        context = new AnnotationConfigApplicationContext(TestWebConfig.class);
    }

    @AfterEach
    void tearDown() {
        context.close();
        TestKeys.uninstall(TestKeys.API_ALIAS);
    }

    @Test
    void encryptResultDeepCopiesAndEncrypts() {
        SampleController controller = context.getBean(SampleController.class);
        UserDTO result = controller.getUser();

        // 深拷贝隔离：返回的是新实例，原始对象保持明文
        assertNotSame(SampleController.lastReturned, result);
        assertEquals("13800138000", SampleController.lastReturned.getPhone());
        assertTrue(CiphertextCodec.looksLikeCiphertext(result.getPhone()));
        assertTrue(CiphertextCodec.looksLikeCiphertext(result.getFriends().get(0).getPhone()));

        // 密文可解回明文
        CachedKeyManager keyManager = context.getBean(CachedKeyManager.class);
        SensitiveCryptoService service = new SensitiveCryptoService(
                new EncryptorFactory(keyManager), FieldMetaCache.getInstance());
        assertEquals("13800138000", service.decryptField(result.getPhone(), TestKeys.API_ALIAS, "phone"));
    }

    @Test
    void decryptParamDecryptsCopyWithoutMutatingOriginal() {
        SampleController controller = context.getBean(SampleController.class);

        CachedKeyManager keyManager = context.getBean(CachedKeyManager.class);
        SensitiveCryptoService service = new SensitiveCryptoService(
                new EncryptorFactory(keyManager), FieldMetaCache.getInstance());
        UserDTO dto = new UserDTO();
        dto.setName("Alice");
        dto.setPhone(service.encryptField("13800138000", TestKeys.API_ALIAS, "phone"));
        String originalPhone = dto.getPhone();

        // 业务方法（save 返回 dto.getPhone()）收到的是解密后的副本 → 返回明文
        String returned = controller.save(dto);
        assertEquals("13800138000", returned);

        // 非侵入原则：原始入参对象保持原样（仍是密文），未被就地修改
        assertEquals(originalPhone, dto.getPhone());
        assertTrue(CiphertextCodec.looksLikeCiphertext(dto.getPhone()));
    }

    @Test
    void encryptResultHandlesResponseEntityBody() {
        SampleController controller = context.getBean(SampleController.class);
        org.springframework.http.ResponseEntity<UserDTO> response = controller.getUserResponseEntity();

        // 返回的 ResponseEntity 是新实例，body 是深拷贝（隔离）
        assertNotSame(SampleController.lastResponseEntityBody, response.getBody());
        // body 中的 phone 已加密
        assertTrue(CiphertextCodec.looksLikeCiphertext(response.getBody().getPhone()));
        // 原始业务对象保持明文（H1 隔离）
        assertEquals("13711112222", SampleController.lastResponseEntityBody.getPhone());
    }

    @Test
    void plainMethodUnaffected() {
        SampleController controller = context.getBean(SampleController.class);
        assertEquals("no-encrypt", controller.plain());
    }

    @Test
    void noDecryptParamMethodLeavesArgsUntouched() {
        SampleController controller = context.getBean(SampleController.class);

        CachedKeyManager keyManager = context.getBean(CachedKeyManager.class);
        SensitiveCryptoService service = new SensitiveCryptoService(
                new EncryptorFactory(keyManager), FieldMetaCache.getInstance());
        UserDTO dto = new UserDTO();
        dto.setName("Eve");
        dto.setPhone(service.encryptField("13800138000", TestKeys.API_ALIAS, "phone"));

        // 无 @DecryptParam：密文原样返回，不做解密
        String echoed = controller.echo(dto);
        assertEquals(dto.getPhone(), echoed);
        assertTrue(CiphertextCodec.looksLikeCiphertext(echoed));
    }
}