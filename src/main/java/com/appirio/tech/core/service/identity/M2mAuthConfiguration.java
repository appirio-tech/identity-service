package com.appirio.tech.core.service.identity;

import com.fasterxml.jackson.annotation.JsonProperty;
import javax.validation.constraints.NotNull;

/**
 * The M2mAuthConfiguration is for configuration.
 * 
 * It's add in Fast 48hrs!! Topcoder Identity Service - Support Event Bus Publishing v1.0
 *
 * @author TCCoder
 * @version 1.0
 */
public class M2mAuthConfiguration {
    /**
     * Represents the clientId attribute
     */
    @JsonProperty
    @NotNull
    private String clientId;

    /**
     * Represents the clientSecret attribute
     */
    @JsonProperty
    @NotNull
    private String clientSecret;

    /**
     * Represents the audience attribute
     */
    @JsonProperty
    @NotNull
    private String audience;

    /**
     * Represents the m2mAuthDomain attribute
     */
    @JsonProperty
    @NotNull
    private String m2mAuthDomain;

    /**
     * Represents the tokenExpireTimeInMinutes attribute
     */
    @JsonProperty
    @NotNull
    private Integer tokenExpireTimeInMinutes;

    /**
     * Represents the userId attribute
     */
    @JsonProperty
    @NotNull

    private Long userId;

    /**
     * Represents the authProxyServerUrl attribute
     */
    @JsonProperty
    private String authProxyServerUrl;

    /**
     * Get clientId
     * 
     * @return the clientId
     */
    public String getClientId() {
        return this.clientId;
    }

    /**
     * Set clientId
     * 
     * @return the clientId to set
     */
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    /**
     * Get clientSecret
     * 
     * @return the clientSecret
     */
    public String getClientSecret() {
        return this.clientSecret;
    }

    /**
     * Set clientSecret
     * 
     * @return the clientSecret to set
     */
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    /**
     * Get audience
     * 
     * @return the audience
     */
    public String getAudience() {
        return this.audience;
    }

    /**
     * Set audience
     * 
     * @return the audience to set
     */
    public void setAudience(String audience) {
        this.audience = audience;
    }

    /**
     * Get m2mAuthDomain
     * 
     * @return the m2mAuthDomain
     */
    public String getM2mAuthDomain() {
        return this.m2mAuthDomain;
    }

    /**
     * Set m2mAuthDomain
     * 
     * @return the m2mAuthDomain to set
     */
    public void setM2mAuthDomain(String m2mAuthDomain) {
        this.m2mAuthDomain = m2mAuthDomain;
    }

    /**
     * Get tokenExpireTimeInMinutes
     * 
     * @return the tokenExpireTimeInMinutes
     */
    public Integer getTokenExpireTimeInMinutes() {
        return this.tokenExpireTimeInMinutes;
    }

    /**
     * Set tokenExpireTimeInMinutes
     * 
     * @return the tokenExpireTimeInMinutes to set
     */
    public void setTokenExpireTimeInMinutes(Integer tokenExpireTimeInMinutes) {
        this.tokenExpireTimeInMinutes = tokenExpireTimeInMinutes;
    }

    /**
     * Get userId
     * 
     * @return the userId
     */
    public Long getUserId() {
        return this.userId;
    }

    /**
     * Set userId
     * 
     * @return the userId to set
     */
    public void setUserId(Long userId) {
        this.userId = userId;
    }

    /**
     * Get authProxyServerUrl
     *
     * @return the authProxyServerUrl
     */
    public String getAuthProxyServerUrl() {
        return this.authProxyServerUrl;
    }

    /**
     * Set authProxyServerUrl
     *
     * @return the authProxyServerUrl to set
     */
    public void setAuthServerProxyUrl(String authProxyServerUrl) {
        this.authProxyServerUrl = authProxyServerUrl;
    }

}
