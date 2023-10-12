package com.appirio.tech.core.service.identity.util.auth;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;

public class DICEAuth {

    @NotNull
    private String diceApiUrl;

    @NotNull
    private String diceApiKey;

    @NotNull
    private String orgId;

    @NotNull
    private String userId;

    @NotNull
    private String tcApiKey;

    @NotNull
    private String schemaName;

    @NotNull
    private String schemaVersion;

    @NotNull
    private Integer otpDuration;

    @NotNull
    private String slackKey;

    @NotNull
    private String slackChannelId;

    public DICEAuth() {
    }

    public DICEAuth(String diceApiUrl, String diceApiKey, String orgId, String userId, String tcApiKey,
            String schemaName, String schemaVersion, Integer otpDuration, String slackKey, String slackChannelId) {
        this.diceApiUrl = diceApiUrl;
        this.diceApiKey = diceApiKey;
        this.orgId = orgId;
        this.userId = userId;
        this.tcApiKey = tcApiKey;
        this.schemaName = schemaName;
        this.schemaVersion = schemaVersion;
        this.otpDuration = otpDuration;
        this.slackKey = slackKey;
        this.slackChannelId = slackChannelId;
    }

    public String getDiceApiUrl() {
        return diceApiUrl;
    }

    public void setDiceApiUrl(String diceApiUrl) {
        this.diceApiUrl = diceApiUrl;
    }

    public String getDiceApiKey() {
        return diceApiKey;
    }

    public void setDiceApiKey(String diceApiKey) {
        this.diceApiKey = diceApiKey;
    }

    public String getOrgId() {
        return orgId;
    }

    public void setOrgId(String orgId) {
        this.orgId = orgId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getTcApiKey() {
        return tcApiKey;
    }

    public void setTcApiKey(String tcApiKey) {
        this.tcApiKey = tcApiKey;
    }

    public String getSchemaName() {
        return schemaName;
    }

    public void setSchemaName(String schemaName) {
        this.schemaName = schemaName;
    }

    public String getSchemaVersion() {
        return schemaVersion;
    }

    public void setSchemaVersion(String schemaVersion) {
        this.schemaVersion = schemaVersion;
    }

    public Integer getOtpDuration() {
        return otpDuration;
    }

    public void setOtpDuration(Integer otpDuration) {
        this.otpDuration = otpDuration;
    }

    public String getSlackKey() {
        return slackKey;
    }

    public void setSlackKey(String slackKey) {
        this.slackKey = slackKey;
    }

    public String getSlackChannelId() {
        return slackChannelId;
    }

    public void setSlackChannelId(String slackChannelId) {
        this.slackChannelId = slackChannelId;
    }

    public boolean isValidAPIKey(HttpServletRequest request) {
        String apiKeyHeader = request.getHeader("X-API-KEY");

        // Check if the X-API-KEY header is present and matches the valid API key
        return apiKeyHeader != null && apiKeyHeader.equals(tcApiKey);
    }
}
