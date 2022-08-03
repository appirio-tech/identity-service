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
    public static final String[] EnableScopes = { "enable:user_2fa", "all:user_2fa" };

    /**
     * Represents the create scopes for machine token validation.
     */
    public static final String[] VerifyScopes = { "verify:user_2fa", "all:user_2fa" };

    /**
     * Represents the update scopes for machine token validation.
     */
    public static final String[] CredentialIssuerScopes = { "cred:user_2fa", "all:user_2fa" };

    /**
     * Represents the enable attribute
     */
    @JsonProperty
    private String enable;

    /**
     * Represents the verify attribute
     */
    @JsonProperty
    private String verify;

    /**
     * Represents the credential attribute
     */
    @JsonProperty
    private String credential;

    public User2faFactory() {
    }

    public String getEnable() {
        return enable;
    }

    public void setEnable(String enable) {
        this.enable = enable;
    }

    public String getVerify() {
        return verify;
    }

    public void SetVerify(String verify) {
        this.verify = verify;
    }

    public String getCredential() {
        return credential;
    }

    public void setCredential(String credential) {
        this.credential = credential;
    }

    /**
     * Gets the enable scopes.
     *
     * @return the enable scopes.
     */
    public String[] getEnableScopes() {
        if (enable != null && enable.trim().length() != 0) {
            return enable.split(SCOPE_DELIMITER);
        }

        return EnableScopes;
    }

    /**
     * Gets the verify scopes.
     *
     * @return the verify scopes.
     */
    public String[] getVerifyScopes() {
        if (verify != null && verify.trim().length() != 0) {
            return verify.split(SCOPE_DELIMITER);
        }

        return VerifyScopes;
    }

    /**
     * Gets the credential issuer scopes.
     *
     * @return the credential issuer scopes.
     */
    public String[] getCredentialIssuerScopes() {
        if (credential != null && credential.trim().length() != 0) {
            return credential.split(SCOPE_DELIMITER);
        }

        return CredentialIssuerScopes;
    }
}
