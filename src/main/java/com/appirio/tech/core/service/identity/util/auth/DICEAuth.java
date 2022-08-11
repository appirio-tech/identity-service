package com.appirio.tech.core.service.identity.util.auth;

import javax.validation.constraints.NotNull;

public class DICEAuth {

    @NotNull
    private String diceUrl;

    @NotNull
    private String diceApiUrl;

    @NotNull
    private String diceVerifier;

    @NotNull
    private String diceApiKey;

    @NotNull
    private String credDefId;

    @NotNull
    private Integer otpDuration;

    private String credPreview = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/credential-preview";

    public DICEAuth() {
    }

    public DICEAuth(String diceUrl, String diceApiUrl, String diceVerifier, String diceApiKey, String credDefId,
            Integer otpDuration) {
        this.diceUrl = diceUrl;
        this.diceApiUrl = diceApiUrl;
        this.diceVerifier = diceVerifier;
        this.diceApiKey = diceApiKey;
        this.credDefId = credDefId;
        this.otpDuration = otpDuration;
    }

    public String getDiceUrl() {
        return diceUrl;
    }

    public void setDiceUrl(String diceUrl) {
        this.diceUrl = diceUrl;
    }

    public String getDiceApiUrl() {
        return diceApiUrl;
    }

    public void setDiceApiUrl(String diceApiUrl) {
        this.diceApiUrl = diceApiUrl;
    }

    public String getDiceVerifier() {
        return diceVerifier;
    }

    public void setDiceVerifier(String diceVerifier) {
        this.diceVerifier = diceVerifier;
    }

    public String getDiceApiKey() {
        return diceApiKey;
    }

    public void setDiceApiKey(String diceApiKey) {
        this.diceApiKey = diceApiKey;
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
}
