package com.appirio.tech.core.service.identity.representation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class DiceTokenResponse {

    @JsonProperty(value = "status")
    private String status;

    @JsonProperty(value = "result")
    private DiceTokenResult result;

    public DiceTokenResult getResult() {
        return result;
    }

    public void setResult(DiceTokenResult result) {
        this.result = result;
    }

    public String getToken() {
        return result.getToken();
    }
}

@JsonIgnoreProperties(ignoreUnknown = true)
class DiceTokenResult {

    @JsonProperty(value = "token")
    private String token;

    @JsonProperty(value = "expires_at")
    private String expiresAt;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(String expiresAt) {
        this.expiresAt = expiresAt;
    }
}