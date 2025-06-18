package com.appirio.tech.core.service.identity.representation;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Member info containing userId, email and handle
 */
public class MemberInfo {

    @JsonProperty("email")
    private String email;

    @JsonProperty("handle")
    private String handle;

    @JsonProperty("userId")
    private Long userId;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getHandle() {
        return handle;
    }

    public void setHandle(String handle) {
        this.handle = handle;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }
}
