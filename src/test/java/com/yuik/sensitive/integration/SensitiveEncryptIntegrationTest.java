package com.yuik.sensitive.integration;

import com.yuik.sensitive.TestKeys;
import com.yuik.sensitive.crypto.CiphertextCodec;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * MyBatis 全链路集成测试：
 * 验证 SqlSessionFactoryBeanPostProcessor 无侵入注入拦截器后，
 * 写库自动加密、查询自动解密（含 List 批量）。
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = TestMyBatisConfig.class)
class SensitiveEncryptIntegrationTest {

    @Autowired
    private SqlSessionFactory sqlSessionFactory;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeAll
    static void installKey() {
        TestKeys.installEnvKey(TestKeys.ALIAS, TestKeys.KEY_B64);
    }

    @AfterAll
    static void uninstallKey() {
        TestKeys.uninstall(TestKeys.ALIAS);
    }

    @BeforeEach
    void createTable() {
        jdbcTemplate.execute("DROP TABLE IF EXISTS t_user");
        jdbcTemplate.execute("CREATE TABLE t_user (id BIGINT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(64), phone VARCHAR(512))");
    }

    @Test
    void insertEncryptsAndSelectDecryptsTransparently() {
        try (SqlSession session = sqlSessionFactory.openSession(true)) {
            UserMapper mapper = session.getMapper(UserMapper.class);

            User user = new User();
            user.setName("Alice");
            user.setPhone("13800138000");
            mapper.insert(user);

            // 落库必须是密文（透传 ParameterHandler 拦截生效）
            String raw = jdbcTemplate.queryForObject(
                    "SELECT phone FROM t_user WHERE id = ?", String.class, user.getId());
            assertNotNull(raw);
            assertNotEquals("13800138000", raw);
            assertTrue(CiphertextCodec.looksLikeCiphertext(raw), "落库值应为标准密文结构");

            // 查询透明解密（ResultSetHandler 拦截生效）
            User back = mapper.selectById(user.getId());
            assertNotNull(back);
            assertEquals("13800138000", back.getPhone());
            assertEquals("Alice", back.getName());
        }
    }

    @Test
    void batchResultDecryptsAllRows() {
        try (SqlSession session = sqlSessionFactory.openSession(true)) {
            UserMapper mapper = session.getMapper(UserMapper.class);
            insertUser(mapper, "A", "13900000001");
            insertUser(mapper, "B", "13900000002");
            insertUser(mapper, "C", "13900000003");

            List<User> users = mapper.selectAll();
            assertEquals(3, users.size());
            assertEquals("13900000001", users.get(0).getPhone());
            assertEquals("13900000002", users.get(1).getPhone());
            assertEquals("13900000003", users.get(2).getPhone());
        }
    }

    @Test
    void updateRoundTripKeepsSingleEncryption() {
        try (SqlSession session = sqlSessionFactory.openSession(true)) {
            UserMapper mapper = session.getMapper(UserMapper.class);
            User user = new User();
            user.setName("Dave");
            user.setPhone("13700000000");
            mapper.insert(user);

            // 模拟先查后改：查询结果已是明文，再写回同一实体不应双重加密
            User loaded = mapper.selectById(user.getId());
            loaded.setName("Dave2");
            mapper.insert(loaded);

            List<User> all = mapper.selectAll();
            assertEquals(2, all.size());
            assertEquals("13700000000", all.get(1).getPhone());
        }
    }

    @Test
    void writePathDoesNotPolluteBusinessEntity() {
        try (SqlSession session = sqlSessionFactory.openSession(true)) {
            UserMapper mapper = session.getMapper(UserMapper.class);

            User user = new User();
            user.setName("M3");
            user.setPhone("13600000000");
            mapper.insert(user);

            // M3 修复：加密-绑定-恢复 —— 写库后业务实体字段必须保持明文
            assertEquals("13600000000", user.getPhone(), "写库后业务实体不应被污染为密文");

            // 落库数据仍为密文
            String raw = jdbcTemplate.queryForObject(
                    "SELECT phone FROM t_user WHERE id = ?", String.class, user.getId());
            assertTrue(CiphertextCodec.looksLikeCiphertext(raw));
        }
    }

    @Test
    void cursorResultDecryptsLazily() {
        try (SqlSession session = sqlSessionFactory.openSession(true)) {
            UserMapper mapper = session.getMapper(UserMapper.class);
            insertUser(mapper, "C1", "13500000001");
            insertUser(mapper, "C2", "13500000002");

            // M1 修复：流式 Cursor 查询逐元素懒解密
            try (org.apache.ibatis.cursor.Cursor<User> cursor = mapper.selectCursor()) {
                int count = 0;
                for (User u : cursor) {
                    assertTrue(u.getPhone().startsWith("1350000000"), "游标元素应被解密");
                    count++;
                }
                assertEquals(2, count);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void insertUser(UserMapper mapper, String name, String phone) {
        User user = new User();
        user.setName(name);
        user.setPhone(phone);
        mapper.insert(user);
    }
}