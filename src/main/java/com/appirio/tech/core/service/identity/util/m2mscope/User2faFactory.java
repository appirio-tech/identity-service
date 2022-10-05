package com.appirio.tech.core.service.identity.util.m2mscope;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * the configurationn for scopes of user 2fa.
 */
public class User2faFactory {

    public static final String SCOPE_DELIMITER = ",";

    /**
     * Represents the dice credential issuer scopes for machine token validation.
     */
    public static final String[] CredentialIssuerScopes = { "cred:user_2fa" };

    /**
     * Represents the credential attribute
     */
    @JsonProperty
    private String credential;

    public User2faFactory() {
    }

    public String getCredential() {
        return credential;
    }

    public void setCredential(String credential) {
        this.credential = credential;
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
