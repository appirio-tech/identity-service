package com.appirio.tech.core.service.identity.util.auth;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;

public class DICEAuth {

    @NotNull
    private String diceApiUrl;

    @NotNull
    private String diceApiKey;

    @NotNull
    private String tcApiKey;

    @NotNull
    private String credDefId;

    @NotNull
    private Integer otpDuration;

    @NotNull
    private String slackKey;

    @NotNull
    private String slackChannelId;

    private String credPreview = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/credential-preview";

    public DICEAuth() {
    }

    public DICEAuth(String diceApiUrl, String diceApiKey, String tcApiKey, String credDefId, Integer otpDuration,
            String slackKey, String slackChannelId) {
        this.diceApiUrl = diceApiUrl;
        this.diceApiKey = diceApiKey;
        this.tcApiKey = tcApiKey;
        this.credDefId = credDefId;
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

    public String getTcApiKey() {
        return tcApiKey;
    }

    public void setTcApiKey(String tcApiKey) {
        this.tcApiKey = tcApiKey;
    }

    public String getCredDefId() {
        return credDefId;
    }

    public void setCredDefId(String credDefId) {
        this.credDefId = credDefId;
    }

    public Integer getOtpDuration() {
        return otpDuration;
    }

    public void setOtpDuration(Integer otpDuration) {
        this.otpDuration = otpDuration;
    }

    public String getCredPreview() {
        return credPreview;
    }

    public void setCredPreview(String credPreview) {
        this.credPreview = credPreview;
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
