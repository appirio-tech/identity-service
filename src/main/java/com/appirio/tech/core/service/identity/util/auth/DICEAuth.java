package com.appirio.tech.core.service.identity.util.auth;

import java.net.HttpURLConnection;
import java.util.Date;

import javax.validation.constraints.NotNull;

import org.apache.log4j.Logger;

import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.util.jwt.InvalidTokenException;
import com.appirio.tech.core.service.identity.util.HttpUtil.Request;
import com.appirio.tech.core.service.identity.util.HttpUtil.Response;
import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;

public class DICEAuth {
    private static final Logger logger = Logger.getLogger(Auth0Client.class);

    @NotNull
    private String diceUrl;

    @NotNull
    private String diceApiUrl;

    @NotNull
    private String diceVerifier;

    @NotNull
    private String tenant;

    @NotNull
    private String username;

    @NotNull
    private String password;

    @NotNull
    private String scope;

    @NotNull
    private String clientId;

    @NotNull
    private String clientSecret;

    @NotNull
    private String credDefId;

    private String credPreview = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/issue-credential/1.0/credential-preview";

    private String cachedToken;

    public DICEAuth() {
    }

    public DICEAuth(String diceUrl, String diceApiUrl, String diceVerifier, String tenant, String username,
            String password, String scope, String clientId, String clientSecret, String credDefId) {
        this.diceUrl = diceUrl;
        this.diceApiUrl = diceApiUrl;
        this.diceVerifier = diceVerifier;
        this.tenant = tenant;
        this.username = username;
        this.password = password;
        this.scope = scope;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
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

    public String getDiceVerifier() {
        return diceVerifier;
    }

    public void setDiceVerifier(String diceVerifier) {
        this.diceVerifier = diceVerifier;
    }

    public String getTenant() {
        return tenant;
    }

    public void setTenant(String tenant) {
        this.tenant = tenant;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
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

    public String getToken() throws Exception {
        Boolean isCachedTokenExpired = false;
        if (cachedToken != null) {
            if (getTokenExpiryTime(cachedToken) <= 0) {
                isCachedTokenExpired = true;
                logger.info("Application cached token expired");
            }
        }
        if (cachedToken == null || isCachedTokenExpired) {
            String url = "https://login.microsoftonline.com/" + getTenant() + "/oauth2/v2.0/token";
            Response response = new Request(url, "POST")
                    .param("grant_type", "password")
                    .param("username", getUsername())
                    .param("password", getPassword())
                    .param("scope", getScope())
                    .param("client_id", getClientId())
                    .param("client_secret", getClientSecret()).execute();
            if (response.getStatusCode() != HttpURLConnection.HTTP_OK) {
                throw new APIRuntimeException(HttpURLConnection.HTTP_INTERNAL_ERROR,
                        String.format("Got unexpected response from remote service. %d %s", response.getStatusCode(),
                                response.getText()));
            }
            cachedToken = new ObjectMapper().readValue(response.getText(), Auth0Credential.class).getIdToken();
            logger.info("Fetched token from URL: " + url);
        }
        return cachedToken;
    }

    /**
     * Get token expiry time in seconds
     *
     * @param token JWT token
     *              throws Exception if any error occurs
     * @return the Integer result
     */
    private Integer getTokenExpiryTime(String token) throws Exception {
        DecodedJWT decodedJWT = null;
        Integer tokenExpiryTime = 0;
        if (token != null) {
            try {
                decodedJWT = JWT.decode(token);
            } catch (JWTDecodeException e) {
                throw new InvalidTokenException(token, "Error occurred in decoding token. " + e.getLocalizedMessage(),
                        e);
            }
            Date tokenExpiryDate = decodedJWT.getExpiresAt();
            Long tokenExpiryTimeInMilliSeconds = tokenExpiryDate.getTime() - (new Date().getTime()) - 60 * 1000;
            tokenExpiryTime = (int) Math.floor(tokenExpiryTimeInMilliSeconds / 1000);
        }
        return tokenExpiryTime;
    }
}
