package com.yuik.sensitive.integration;

import com.yuik.sensitive.annotation.EncryptField;

/**
 * 集成测试实体：phone 字段标注加密。
 */
public class User {

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