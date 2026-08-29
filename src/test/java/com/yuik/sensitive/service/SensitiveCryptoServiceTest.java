package com.yuik.sensitive.service;

import com.yuik.sensitive.TestKeys;
import com.yuik.sensitive.annotation.EncryptField;
import com.yuik.sensitive.crypto.EncryptorFactory;
import com.yuik.sensitive.crypto.CiphertextCodec;
import com.yuik.sensitive.key.CachedKeyManager;
import com.yuik.sensitive.key.EnvKeyProvider;
import com.yuik.sensitive.metadata.FieldMetaCache;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SensitiveCryptoServiceTest {

    public static class UserEntity {
        /** 非 String 类型却标注了 @EncryptField —— 组件必须安全跳过（@EncryptField 仅支持 String）。 */
        @EncryptField(keyAlias = "db-phone")
        private Long id;
        private String name;

        @EncryptField(keyAlias = "db-phone")
        private String phone;

        public Long getId() {
            return id;
        }

        public void setId(Long id) {
            this.id = id;
        }

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
    }

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

    private CachedKeyManager keyManager;
    private SensitiveCryptoService service;

    @BeforeEach
    void setUp() {
        TestKeys.installEnvKey(TestKeys.ALIAS, TestKeys.KEY_B64);
        TestKeys.installEnvKey(TestKeys.API_ALIAS, TestKeys.KEY_B64_OTHER);
        keyManager = new CachedKeyManager(new EnvKeyProvider());
        keyManager.afterPropertiesSet();
        service = new SensitiveCryptoService(new EncryptorFactory(keyManager), FieldMetaCache.getInstance());
    }

    @AfterEach
    void tearDown() {
        keyManager.destroy();
        TestKeys.uninstall(TestKeys.ALIAS);
        TestKeys.uninstall(TestKeys.API_ALIAS);
    }

    @Test
    void fieldRoundTrip() {
        String cipher = service.encryptField("13800138000", TestKeys.ALIAS, "phone");
        assertTrue(CiphertextCodec.looksLikeCiphertext(cipher));
        assertEquals("13800138000", service.decryptField(cipher, TestKeys.ALIAS, "phone"));
    }

    @Test
    void nullAndEmptyPassthrough() {
        assertEquals(null, service.encryptField(null, TestKeys.ALIAS, "phone"));
        assertEquals("", service.encryptField("", TestKeys.ALIAS, "phone"));
        assertEquals(null, service.decryptField(null, TestKeys.ALIAS, "phone"));
        assertEquals("", service.decryptField("", TestKeys.ALIAS, "phone"));
    }

    @Test
    void decryptFailureDegradesToPlaceholder() {
        // 篡改密文：结构合法（Base64 + 版本 + IV + 长度）但 GCM Tag 校验失败 → 降级占位符
        String cipher = service.encryptField("13800138000", TestKeys.ALIAS, "phone");
        char[] chars = cipher.toCharArray();
        chars[chars.length - 1] = chars[chars.length - 1] == 'A' ? 'B' : 'A';
        assertEquals("***", service.decryptField(new String(chars), TestKeys.ALIAS, "phone"));
    }

    @Test
    void decryptFieldReturnsDirtyPlaintextAsIs() {
        // M4 修复：结构上不是本组件密文的值（脏明文 / 普通文本）按"返回原值"语义原样返回
        assertEquals("脏数据或者乱码", service.decryptField("脏数据或者乱码", TestKeys.ALIAS, "phone"));
        assertEquals("!!!bad!!!", service.decryptField("!!!bad!!!", TestKeys.ALIAS, "phone"));
    }

    @Test
    void decryptFieldIsIdempotent() {
        // M4 修复：已解密过的明文再次解密不会被破坏为占位符
        String cipher = service.encryptField("13800138000", TestKeys.ALIAS, "phone");
        String first = service.decryptField(cipher, TestKeys.ALIAS, "phone");
        assertEquals("13800138000", first);
        assertEquals("13800138000", service.decryptField(first, TestKeys.ALIAS, "phone"));
    }

    @Test
    void decryptFailurePlaceholderConfigurable() {
        service.setDecryptFailPlaceholder("******");
        // 结构合法的篡改密文 → 可配置占位符生效
        String cipher = service.encryptField("13800138000", TestKeys.ALIAS, "phone");
        char[] chars = cipher.toCharArray();
        chars[chars.length - 2] = chars[chars.length - 2] == 'A' ? 'B' : 'A';
        assertEquals("******", service.decryptField(new String(chars), TestKeys.ALIAS, "phone"));
    }

    @Test
    void snapshotRestoreIsolatesOriginal() {
        // M3 修复：快照加密 → 恢复后业务实体保持明文（MyBatis 写库路径隔离）
        UserEntity user = new UserEntity();
        user.setId(1L);
        user.setName("Snap");
        user.setPhone("13800138000");

        SensitiveCryptoService.FieldSnapshot snapshot = service.encryptObjectFieldsWithSnapshot(user);
        assertTrue(CiphertextCodec.looksLikeCiphertext(user.getPhone()), "加密后应为密文");

        service.restoreFields(snapshot);
        assertEquals("13800138000", user.getPhone(), "恢复后业务实体应保持明文");
        assertEquals("Snap", user.getName());
    }

    @Test
    void noDoubleEncryption() {
        String plain = "13800138000";
        String once = service.encryptField(plain, TestKeys.ALIAS, "phone");
        // 再次加密已识别为密文，直接跳过
        String twice = service.encryptField(once, TestKeys.ALIAS, "phone");
        assertEquals(once, twice);
        assertEquals(plain, service.decryptField(twice, TestKeys.ALIAS, "phone"));
    }

    @Test
    void flatObjectEncryptAndDecrypt() {
        UserEntity user = new UserEntity();
        user.setId(1L);
        user.setName("Alice");
        user.setPhone("13800138000");

        service.encryptObjectFields(user);
        assertTrue(CiphertextCodec.looksLikeCiphertext(user.getPhone()));
        assertEquals("Alice", user.getName()); // 未注解字段不受影响

        service.decryptObjectFields(user);
        assertEquals("13800138000", user.getPhone());
    }

    @Test
    void deepCopyAndEncryptIsolatesOriginal() {
        UserDTO dto = new UserDTO();
        dto.setName("Alice");
        dto.setPhone("13800138000");
        UserDTO friend = new UserDTO();
        friend.setName("Bob");
        friend.setPhone("13900000000");
        dto.setFriends(new ArrayList<>(Arrays.asList(friend)));

        Object result = service.deepCopyAndEncrypt(dto);
        assertNotSame(dto, result);

        UserDTO copy = (UserDTO) result;
        // 副本被加密
        assertTrue(CiphertextCodec.looksLikeCiphertext(copy.getPhone()));
        assertTrue(CiphertextCodec.looksLikeCiphertext(copy.getFriends().get(0).getPhone()));
        // 原始对象保持明文（深拷贝隔离）
        assertEquals("13800138000", dto.getPhone());
        assertEquals("13900000000", dto.getFriends().get(0).getPhone());
    }

    @Test
    void decryptTreeDecryptsNested() {
        UserDTO dto = new UserDTO();
        dto.setName("Alice");
        dto.setPhone(service.encryptField("13800138000", TestKeys.API_ALIAS, "phone"));
        UserDTO friend = new UserDTO();
        friend.setName("Bob");
        friend.setPhone(service.encryptField("13900000000", TestKeys.API_ALIAS, "phone"));
        dto.setFriends(new ArrayList<>(Arrays.asList(friend)));

        service.decryptTree(dto);
        assertEquals("13800138000", dto.getPhone());
        assertEquals("13900000000", dto.getFriends().get(0).getPhone());
    }

    @Test
    void encryptObjectFieldsIgnoresNonStringEncryptedField() {
        // Long 字段带 @EncryptField —— 应被安全跳过（不加密、不抛异常），String 字段正常加密
        UserEntity user = new UserEntity();
        user.setId(1L);
        user.setName("Alice");
        user.setPhone("13800138000");
        service.encryptObjectFields(user);
        assertEquals(Long.valueOf(1L), user.getId());
        assertTrue(CiphertextCodec.looksLikeCiphertext(user.getPhone()));

        // 解密路径同样安全跳过非 String 字段
        service.decryptObjectFields(user);
        assertEquals(Long.valueOf(1L), user.getId());
        assertEquals("13800138000", user.getPhone());
    }
}