package com.yuik.sensitive.integration;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.cursor.Cursor;

import java.util.List;

/**
 * 注解式 Mapper：验证拦截器在真实 MyBatis 执行链中的透明加解密。
 */
public interface UserMapper {

    @Insert("INSERT INTO t_user(name, phone) VALUES(#{name}, #{phone})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int insert(User user);

    @Select("SELECT id, name, phone FROM t_user WHERE id = #{id}")
    User selectById(Long id);

    @Select("SELECT id, name, phone FROM t_user ORDER BY id")
    List<User> selectAll();

    /** 流式 Cursor 查询：验证 M1 修复（游标元素懒解密）。 */
    @Select("SELECT id, name, phone FROM t_user ORDER BY id")
    Cursor<User> selectCursor();
}