package com.appirio.tech.core.service.identity.util.auth;

import javax.validation.constraints.NotNull;

public class DICEAuth {

    @NotNull
    private String diceApiUrl;

    @NotNull
    private String diceApiKey;

    @NotNull
    private String credDefId;

    @NotNull
    private Integer otpDuration;

    private String credPreview = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/credential-preview";

    public DICEAuth() {
    }

    public DICEAuth(String diceApiUrl, String diceApiKey, String credDefId, Integer otpDuration) {
        this.diceApiUrl = diceApiUrl;
        this.diceApiKey = diceApiKey;
        this.credDefId = credDefId;
        this.otpDuration = otpDuration;
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
