package com.appirio.tech.core.service.identity.util.auth;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;

import org.apache.log4j.Logger;

import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.util.jwt.InvalidTokenException;
import com.appirio.tech.core.service.identity.representation.DiceTokenResponse;
import com.appirio.tech.core.service.identity.util.HttpUtil.Request;
import com.appirio.tech.core.service.identity.util.HttpUtil.Response;
import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class DICEAuth {
    private static final Logger logger = Logger.getLogger(DICEAuth.class);

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

    private static String cachedToken;

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

    private static Integer getTokenExpiryTime(String token) {
        DecodedJWT decodedJWT = null;
        Integer tokenExpiryTime = 0;
        if (token != null) {
            try {
                decodedJWT = JWT.decode(token);
            } catch (JWTDecodeException var6) {
                throw new InvalidTokenException(token,
                        "Error occurred in decoding token. " + var6.getLocalizedMessage(), var6);
            }

            Date tokenExpiryDate = decodedJWT.getExpiresAt();
            Long tokenExpiryTimeInMilliSeconds = tokenExpiryDate.getTime() - (new Date()).getTime() - 60000L;
            tokenExpiryTime = (int) Math.floor((double) (tokenExpiryTimeInMilliSeconds / 1000L));
        }

        return tokenExpiryTime;
    }

    public static String getDiceAuthToken(String diceApiUrl, String userId, String orgId, String apiKey)
            throws JsonParseException, JsonMappingException, IOException {
        Boolean isAppCachedTokenExpired = false;
        if (cachedToken != null && getTokenExpiryTime(cachedToken) <= 0) {
            isAppCachedTokenExpired = true;
        }
        if (cachedToken == null || isAppCachedTokenExpired) {
            Response response;
            try {
                response = new Request(diceApiUrl + "api-token", "GET").header("org_id", orgId)
                        .header("invoked_by", userId).header("x-api-key", apiKey).execute();
            } catch (Exception e) {
                logger.error("Error when calling dice auth token api", e);
                throw new APIRuntimeException(500, "Error when calling dice connection api");
            }
            if (response.getStatusCode() != HttpURLConnection.HTTP_OK) {
                throw new APIRuntimeException(HttpURLConnection.HTTP_INTERNAL_ERROR,
                        String.format("Got unexpected response from remote service dice token. %d %s",
                                response.getStatusCode(), response.getMessage()));
            }
            DiceTokenResponse tokenResponse = new ObjectMapper().readValue(response.getText(),
                    DiceTokenResponse.class);
            cachedToken = tokenResponse.getToken();
        }
        return cachedToken;
    }
}
