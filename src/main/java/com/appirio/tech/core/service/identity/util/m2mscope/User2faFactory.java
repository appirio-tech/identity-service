package com.appirio.tech.core.service.identity.util.m2mscope;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * the configurationn for scopes of user 2fa.
 */
public class User2faFactory {

    public static final String SCOPE_DELIMITER = ",";

    /**
     * Represents the create scopes for machine token validation.
     */
    public static final String[] ReadScopes = { "all:user_2fa" };

    /**
     * Represents the create scopes for machine token validation.
     */
    public static final String[] CreateScopes = { "all:user_2fa" };

    /**
     * Represents the delete scopes for machine token validation.
     */
    public static final String[] DeleteScopes = { "all:user_2fa" };

    /**
     * Represents the update scopes for machine token validation.
     */
    public static final String[] UpdateScopes = { "all:user_2fa" };

    /**
     * Represents the read attribute
     */
    @JsonProperty
    private String read;

    /**
     * Represents the create attribute
     */
    @JsonProperty
    private String create;

    /**
     * Represents the update attribute
     */
    @JsonProperty
    private String update;

    /**
     * Represents the delete attribute
     */
    @JsonProperty
    private String delete;

    public User2faFactory() {
    }

    public String getRead() {
        return read;
    }

    public void setRead(String read) {
        this.read = read;
    }

    public String getCreate() {
        return create;
    }

    public void setCreate(String create) {
        this.create = create;
    }

    public String getUpdate() {
        return update;
    }

    public void setUpdate(String update) {
        this.update = update;
    }

    public String getDelete() {
        return delete;
    }

    public void setDelete(String delete) {
        this.delete = delete;
    }

    /**
     * Gets the read scopes.
     *
     * @return the read scopes.
     */
    public String[] getReadScopes() {
        if (read != null && read.trim().length() != 0) {
            return read.split(SCOPE_DELIMITER);
        }

        return ReadScopes;
    }

    /**
     * Gets the create scopes.
     *
     * @return the create scopes.
     */
    public String[] getCreateScopes() {
        if (create != null && create.trim().length() != 0) {
            return create.split(SCOPE_DELIMITER);
        }

        return CreateScopes;
    }

    /**
     * Gets the update scopes.
     *
     * @return the update scopes.
     */
    public String[] getUpdateScopes() {
        if (update != null && update.trim().length() != 0) {
            return update.split(SCOPE_DELIMITER);
        }

        return UpdateScopes;
    }

    /**
     * Gets the delete scopes.
     *
     * @return the delete scopes.
     */
    public String[] getDeleteScopes() {
        if (delete != null && delete.trim().length() != 0) {
            return delete.split(SCOPE_DELIMITER);
        }

        return DeleteScopes;
    }
}
