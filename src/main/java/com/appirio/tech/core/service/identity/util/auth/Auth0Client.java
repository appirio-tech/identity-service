package com.appirio.tech.core.service.identity.util.auth;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.validation.constraints.NotNull;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.service.identity.util.HttpUtil.Request;
import com.appirio.tech.core.service.identity.util.HttpUtil.Response;
import com.appirio.tech.core.service.identity.util.Utils;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Auth0Client is used to get/refresh/revoke the tokens for the client.
 * 
 * <p>
 *  Version 1.1 (Topcoder - Provide Way to Refresh Auth0 Tokens In authorizations API v1.0)
 *  - modify getToken to get the refresh token
 *  - add refreshToken to refresh the token
 *  - verifyToken is changed to use the classes from java jwt version 3.2.0
 * </p>
 * 
 * @author TCCoder
 * @version 1.1
 *
 */

public class Auth0Client {
	
	private static final Logger logger = Logger.getLogger(Auth0Client.class);

	@NotNull
	private String clientId;
	
	@NotNull
	private String clientSecret;

	@NotNull
	private String nonInteractiveClientId;
	
	@NotNull
	private String nonInteractiveClientSecret;

	@NotNull
	private String domain;
	
	private String proxyServerUrl;
	
	public Auth0Client(){}
	
	public Auth0Client(String clientId, String clientSecret,
						String nonInteractiveClientId, String nonInteractiveClientSecret,
						String domain, String proxyServerUrl) {
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.nonInteractiveClientId = nonInteractiveClientId;
		this.nonInteractiveClientSecret = nonInteractiveClientSecret;
		this.domain = domain;
		this.proxyServerUrl = proxyServerUrl;
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
	public String getNonInteractiveClientId() {
		return nonInteractiveClientId;
	}
	public void setNonInteractiveClientId(String nonInteractiveClientId) {
		this.nonInteractiveClientId = nonInteractiveClientId;
	}
	public String getNonInteractiveClientSecret() {
		return nonInteractiveClientSecret;
	}
	public void setNonInteractiveClientSecret(String nonInteractiveClientSecret) {
		this.nonInteractiveClientSecret = nonInteractiveClientSecret;
	}
	public String getDomain() {
		return domain;
	}
	public void setDomain(String domain) {
		this.domain = domain;
	}
	protected Request createRequest(String endpoint, String method) {
		return new Request(endpoint, method);
	}

	public String getProxyServerUrl() {
		return proxyServerUrl;
	}

	public void setProxyServerUrl(String proxyServerUrl) {
		this.proxyServerUrl = proxyServerUrl;
	}

	
	/**
     * Get auth token with access token and refresh token by authorizaton code and redirect url.
     *
     * @param code the authorization code to use
     * @param redirectUrl the redirectUrl to use
     * @throws Exception if any error occurs
     * @return the Auth0Credential result
     */
    public Auth0Credential getToken(String code, String redirectUrl) throws Exception {
        
		Response response =
				createRequest("https://"+getDomain()+"/oauth/token", "POST")
					.param("client_id", clientId)
					.param("redirect_uri", redirectUrl)
					.param("client_secret", clientSecret)
					.param("code", code)
					.param("grant_type", "authorization_code")
					.param("scope", "openid offline_access")
					.execute();
		
		
		if(response.getStatusCode() != HttpURLConnection.HTTP_OK) {
			throw new APIRuntimeException(HttpURLConnection.HTTP_INTERNAL_ERROR,
					String.format("Got unexpected response from remote service. %d %s", response.getStatusCode(), response.getMessage()));
		}
		return new ObjectMapper().readValue(response.getText(), Auth0Credential.class);			
	}
    
    /**
     * Get the new access token by refresh token.
     *
     * @param refreshToken the refreshToken to use
     * @throws Exception if any error occurs
     * @return the Auth0Credential result contains the new access token
     */
    public Auth0Credential refreshToken(String refreshToken) throws Exception {
        Response response =
                createRequest("https://"+getDomain()+"/oauth/token", "POST")
                    .param("client_id", clientId)
                    .param("client_secret", clientSecret)
                    .param("refresh_token", refreshToken)
                    .param("grant_type", "refresh_token")
                    .execute();
        if(response.getStatusCode() != HttpURLConnection.HTTP_OK) {
            throw new APIRuntimeException(HttpURLConnection.HTTP_INTERNAL_ERROR,
                    String.format("Got unexpected response from remote service. %d %s", response.getStatusCode(), response.getMessage()));
        }
        return new ObjectMapper().readValue(response.getText(), Auth0Credential.class);         
    }
	
	public Auth0Credential refresh(String refreshToken) throws Exception {
		Response response =
			createRequest("https://"+getDomain()+"/delegation", "POST")
				.param("client_id", clientId)
				.param("client_secret", clientSecret)
				.param("refresh_token", refreshToken)
				.param("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
				.param("target", clientId)
				.param("scope", "passthrough")
				.param("api_type", "auth0").execute();
		
		if(response.getStatusCode() != HttpURLConnection.HTTP_OK) {
			throw new APIRuntimeException(HttpURLConnection.HTTP_INTERNAL_ERROR,
					String.format("Got unexpected response from remote service. %d %s", response.getStatusCode(), response.getMessage()));
		}
		return new ObjectMapper().readValue(response.getText(), Auth0Credential.class);
	}
	
	public void revokeRefreshToken(String token, String refreshToken) throws Exception {
		String userId = getUserIdFromToken(token);
		Response response =
				createRequest("https://"+getDomain()+"/api/users/"+userId+"/refresh_tokens/"+refreshToken, "DELETE")
					.header("Authorization", "Bearer "+token)
					.execute();
		if(response.getStatusCode() != HttpURLConnection.HTTP_OK) {
			throw new APIRuntimeException(HttpURLConnection.HTTP_INTERNAL_ERROR,
					String.format("Got unexpected response from remote service. %d %s", response.getStatusCode(), response.getMessage()));
		}
	}
	
	public Auth0Credential getTokenFromNonInteractiveClient() throws Exception {
		Map<String, String> body = new HashMap<>();
		body.put("client_id", this.nonInteractiveClientId);
		body.put("client_secret", this.nonInteractiveClientSecret);
		body.put("audience", "https://"+getDomain()+"/api/v2/");
		body.put("grant_type", "client_credentials");

		String auth0Url = "https://"+getDomain()+"/oauth/token";
		
		if (getProxyServerUrl() != null) {
			body.put("auth0_url", auth0Url);
			auth0Url = getProxyServerUrl();
		}

		Response response =
				createRequest(auth0Url, "POST")
				.json(new ObjectMapper().writeValueAsString(body))
				.execute();
		
		if(response.getStatusCode() != HttpURLConnection.HTTP_OK) {
			throw new APIRuntimeException(HttpURLConnection.HTTP_INTERNAL_ERROR,
					String.format("Got unexpected response from remote service. %d %s", response.getStatusCode(), response.getMessage()));
		}
		return new ObjectMapper().readValue(response.getText(), Auth0Credential.class);	
	}
	
	public String getIdProviderAccessToken(String auth0UserId) throws Exception {
		Auth0Credential cred = getTokenFromNonInteractiveClient();
		Response response =
				createRequest("https://"+getDomain()+"/api/v2/users/"+URLEncoder.encode(auth0UserId, "UTF-8"), "GET")
					.header("Authorization", "Bearer "+cred.getAccessToken())
					.execute();
		
		if(response.getStatusCode() != HttpURLConnection.HTTP_OK) {
			throw new APIRuntimeException(HttpURLConnection.HTTP_INTERNAL_ERROR,
					String.format("Got unexpected response from remote service. %d %s", response.getStatusCode(), response.getMessage()));
		}
		
		Map<String, Object> identity = extractIdentity(response.getText(), auth0UserId);
		if(identity==null)
			return null; //TODO: error?
		return (String)identity.get("access_token");
	}
	
	@SuppressWarnings({ "unchecked", "rawtypes" })
	protected Map<String, Object> extractIdentity(String rawUserDataJson, String auth0UserId) throws Exception {
		if(rawUserDataJson==null || rawUserDataJson.trim().length()==0)
			return null;
		int p = auth0UserId!=null ? auth0UserId.indexOf("|") : -1;
		String provider = p>=0 ? auth0UserId.substring(0, p) : null;
		
		Map<String, Object> userData = new ObjectMapper().readValue(rawUserDataJson, new TypeReference<Map<String, Object>>() {});
		if(!userData.containsKey("identities")) {
			logger.warn("User data contain no 'identities'. Auth0 userId: "+auth0UserId);
			return null;
		}
		if(!(userData.get("identities") instanceof List)) {
			logger.warn("'identities' is supposed to be java.util.Array, but it's " + userData + ". Auth0 userId: "+auth0UserId);			
			return null;
		}
			
		List identities = (List)userData.get("identities");
		if(identities.size()==0) {
			logger.warn("'identities' has no element. Auth0 userId: "+auth0UserId);
			return null;
		}
		
		if(provider==null)
			return (Map<String, Object>)identities.get(0);
		
		for(Object elem : identities) {
			if(!(elem instanceof Map))
				continue;
			Map<String, Object> identity = (Map<String, Object>)elem;
			if(provider.equalsIgnoreCase((String)identity.get("provider"))) {
				return identity;
			}
		}

		logger.warn("'identities' has no element whose 'provider' is '" + provider + "'. Auth0 userId: "+auth0UserId);
		return null;
	}
	
	private String getUserIdFromToken(String token) throws Exception {
		Map<String, Object> claims = Utils.parseJWTClaims(token);
		String userId = (String)claims.get("user_id");
		if(userId==null)
			userId = (String)claims.get("sub"); // try to get userId from "sub" claim.
		return userId;
	}

	/**
     * Verify token
     * It's changed to use the classes from java jwt version 3.2.0
     *
     * @param token the token to use
     * @throws IOException if any error occurs
     * @throws InvalidKeyException if any error occurs
     * @throws NoSuchAlgorithmException if any error occurs
     * @throws SignatureException if any error occurs
     * @throws TokenExpiredException if any error occurs
     * @return the Map<String,Object> result contains the claims
     */
    public Map<String, Object> verifyToken(String token) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, TokenExpiredException {
	    Algorithm alg = Algorithm.HMAC256(Base64.decodeBase64(clientSecret));
        Verification verification = JWT.require(alg);
        JWTVerifier verifier = verification.build();
        verifier.verify(token);
        try {
            return Utils.parseJWTClaims(token);
        } catch (Exception exp) {
            // will never catch the exp here as the token is deem valid at the step
            return null;
        }
	}
	
	public static void main(String[] args) throws Exception {
	}
}
