package com.appirio.tech.core.service.identity.util.auth;

import javax.validation.constraints.NotNull;

public class DICEAuth {
    @NotNull
    private String diceUrl;

    @NotNull
    private String diceApiUrl;

    @NotNull
    private String apiKey;

    @NotNull
    private String credDefId;

    private String credPreview = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/credential-preview";

    public DICEAuth() {
    }

    public DICEAuth(String diceUrl, String diceApiUrl, String apiKey, String credDefId) {
        this.diceUrl = diceUrl;
        this.diceApiUrl = diceApiUrl;
        this.apiKey = apiKey;
        this.credDefId = credDefId;
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

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getCredDefId() {
        return credDefId;
    }

    public void setCredDefId(String credDefId) {
        this.credDefId = credDefId;
    }

    public String getCredPreview() {
        return credPreview;
    }

    public void setCredPreview(String credPreview) {
        this.credPreview = credPreview;
    }
}
