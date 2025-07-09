/**
 * Copyright (C) 2017-2018 Topcoder Inc., All Rights Reserved.
 */
package com.appirio.tech.core.service.identity.util;

import static com.appirio.tech.core.service.identity.util.Constants.*;
import static javax.servlet.http.HttpServletResponse.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.HttpHeaders;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.util.jwt.JWTToken;
import com.appirio.tech.core.api.v3.util.jwt.JWTTokenGenerator;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.IdentityApplication;
import com.appirio.tech.core.service.identity.M2mAuthConfiguration;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Utils.
 * 
 * <p>
 * Version 1.1 - GROUP AND MEMBERSHIP MANAGEMENT API
 * - Added checkStringLength method
 * </p>
 * 
 * <p>
 * Changes in the verstion 1.2 (Topcoder - Provide Way to Refresh Auth0 Tokens In authorizations API v1.0)
 * - add parseJWTHeader method
 * </p>
 * 
 * <p>
 * Version 1.3 - Fast 48hrs!! Topcoder Identity Service - Support Event Bus Publishing v1.0
 * - add methods to generate m2m token from m2m configuration and get valid token issuers
 * </p>
 *
 * @author TCSCODER
 * @version 1.3 
 */
public class Utils {
	
	private static final Logger logger = Logger.getLogger(Utils.class);

	public static final String CONTEXT_KEY_DEFAULT_PASSWORD = "defaultPassword";
	public static final String CONTEXT_KEY_PASSWORD_HASH = "passwordHashKey";

	private static final Map<String, Object> applicationContext = new LinkedHashMap<String, Object>();

	/**
	 * Represents the admin roles
	 */
	public static final String[] AdminRoles = {"administrator"};

	/**
     * The VALID_ISSUERS field 
     */
	private static final List<String> VALID_ISSUERS = new ArrayList<>();
    static {
        String validIssuersStr = System.getenv(IdentityApplication.PROP_KEY_VALID_ISSUERS);
        if (validIssuersStr != null) {
            VALID_ISSUERS.addAll(Arrays.asList(validIssuersStr.split(",")));
        }
    }
    
    /**
     * Get valid issuers
     *
     * @return the List<String> result
     */
    public static List<String> getValidIssuers() {
        return new ArrayList<String>(VALID_ISSUERS);
    }
    
    /**
     * Generate m2m token.
     *
     * @param m2mAuthConfiguration
     * @return the token
     * @throws Exception if any error occurs
     */
    public static String generateAuthToken(M2mAuthConfiguration m2mAuthConfiguration) throws Exception{
        JWTTokenGenerator jwtTokenGenerator = JWTTokenGenerator.getInstance(m2mAuthConfiguration.getClientId(),
                m2mAuthConfiguration.getClientSecret(),
                m2mAuthConfiguration.getAudience(),
                m2mAuthConfiguration.getM2mAuthDomain(),
                m2mAuthConfiguration.getTokenExpireTimeInMinutes(),
                m2mAuthConfiguration.getAuthProxyServerUrl());
        return jwtTokenGenerator.getMachineToken();
    }
	
	public static void setApplicationContext(Map<String, Object> context) {
		applicationContext.clear();
		applicationContext.putAll(context);
	}
	
	public static Object getContext(String key) {
		return applicationContext.get(key);
	}
	
	public static String getString(String key) {
		Object val = getContext(key);
		return val!=null ? String.valueOf(val) : null;
	}

	public static String getString(String key, String defaultVal) {
		String val = getString(key);
		return val!=null ? val : defaultVal;
	}
	
	public static Integer getInteger(String key) {
		Object val = getContext(key);
		if(val==null)
			return null;
		if(val instanceof Integer)
			return (Integer) val;
		return Integer.valueOf(String.valueOf(val));
	}

	public static Integer getInteger(String key, int defaultVal) {
		Integer val = getInteger(key);
		return val!=null ? val : defaultVal;
	}

	public static String getEncodedDefaultPassword() {
		return encodePassword(getString(CONTEXT_KEY_DEFAULT_PASSWORD));
	}
	
	/**
	 * Encrypt the password using the key configured in the application.
	 */
	public static String encodePassword(String password) {
		return encodePassword(password, getString(CONTEXT_KEY_PASSWORD_HASH, "default"));
	}
	
	/**
	 * Encrypt the password using the specified key. After being
	 * encrypted with a Blowfish key, the encrypted byte array is
	 * then encoded with a base 64 encoding, resulting in the String
	 * that is returned.
	 *
	 * @param password The password to encrypt.
	 * @param key The base 64 encoded Blowfish key.
	 * @return the encrypted and encoded password
	 */
	public static String encodePassword(String password, String key) {
		if(password==null)
			throw new IllegalArgumentException("password must be specified.");
		if(key==null)
			throw new IllegalArgumentException("key must be specified.");
		try {
			logger.error("Key: " + key + " Decoded: " + Base64.decodeBase64(key));
			SecretKeySpec sksSpec = new SecretKeySpec(Base64.decodeBase64(key), "Blowfish");
			Cipher cipher = Cipher.getInstance("Blowfish");
			cipher.init(Cipher.ENCRYPT_MODE, sksSpec);
			byte[] encrypted = cipher.doFinal(password.getBytes("UTF-8"));
			//logger.info(String.format(" password. (password=%s)", password));
			//logger.info(String.format(" key (key=%s)",key));
			//logger.info(String.format("decode password. (encoded=%s)", encrypted));
			//logger.info(String.format("base 64 decode password. (encoded=%s)", new String(Base64.encodeBase64(encrypted))));
			//return Base64.encodeBase64String(encrypted);
			return new String(Base64.encodeBase64(encrypted));
		} catch (Exception e) {
			logger.error(String.format("Failed to encode password. (password=%s, key=%s) error: %s", password, key, e.getLocalizedMessage()), e);
			throw new RuntimeException("Failed to encode password. "+e.getLocalizedMessage(), e);
		}
	}
	
	/**
	 * Decrypt the password using the key configured in the application.
	 *
	 * @param password base64 encoded string.
	 * @return the decypted password
	 */
	public static String decodePassword(String encodedPassword) {
		return decodePassword(encodedPassword, getString(CONTEXT_KEY_PASSWORD_HASH, "default"));
	}
	
	/**
	 * Decrypt the password using the specified key. Takes a password
	 * that has been ecrypted and encoded, uses base 64 decoding and
	 * Blowfish decryption to return the original string.
	 *
	 * @param password base64 encoded string.
	 * @param key The base 64 encoded Blowfish key.
	 * @return the decypted password
	 */
	public static String decodePassword(String encodedPassword, String key) {
		try {
			SecretKeySpec sksSpec = new SecretKeySpec(Base64.decodeBase64(key), "Blowfish");
			Cipher cipher = Cipher.getInstance("Blowfish");
			cipher.init(Cipher.DECRYPT_MODE, sksSpec);
			byte[] decrypted = cipher.doFinal(Base64.decodeBase64(encodedPassword));
			return new String(decrypted, "UTF-8");
		} catch (Exception e) {
			logger.error(String.format("Failed to decode password. (encoded=%s, key=%s) error: %s", encodedPassword, key, e.getLocalizedMessage()), e);
			throw new RuntimeException("Failed to decode password. "+e.getLocalizedMessage(), e);
		}
	}
  

	/**
	 * This is used to generate reset token.
	 * @param charSpace
	 * @param length
	 * @return
	 */
	public static final String generateRandomString(String charSpace, int length) {
		if(charSpace==null)
			throw new IllegalArgumentException("charSpace must be specified.");
		if(length<=0)
			throw new IllegalArgumentException("length must be positive.");
		
		StringBuffer token = new StringBuffer();
		Random random = new Random(new Date().getTime());
		for (int i = 0; i < length; i++) {
			token.append(charSpace.charAt(random.nextInt(charSpace.length())));
		}
		return token.toString();
	}
	
	public static boolean containsOnly(String string, String alphabet, boolean wsAllowed) {
		int n = string.length();
		for (int i = 0; i < n; ++i) {
			char ch = string.charAt(i);
			int foundAt = alphabet.indexOf(ch);
			if (foundAt < 0) {
				if (wsAllowed) {
					if (ALPHABET_WHITESPACE_EN.indexOf(ch) >= 0) continue;
				}
				return false;
			}
		}
		return true;
	}
	
	public static boolean isValid(TCID id) {
		if(id==null)
			return false;
		try {
			return toLongValue(id) > 0;
		} catch (Exception e) {
			logger.debug("Utils#isValid(): TCID is invalid. "+e.getMessage());
			return false;
		}
	}
	
	// package com.topcoder.web.common.StringUtils#getActivationCode
	public static String getActivationCode(long coderId) {
		String id = Long.toString(coderId);
		String hash = new BigInteger(new BigInteger(id).bitLength(),
				new Random(coderId)).add(new BigInteger("TopCoder", 36))
				.toString();
		while (hash.length() < id.length()) {
			hash = "0" + hash;
		}
		hash = hash.substring(hash.length() - id.length());
		return new BigInteger(id + hash).toString(36).toUpperCase();
	}

	// package com.topcoder.web.common.StringUtils#getCoderId
	public static int getCoderId(String activationCode) {
		try {
			String idhash = new BigInteger(activationCode, 36).toString();
			if (idhash.length() % 2 != 0)
				return 0;
			String id = idhash.substring(0, idhash.length() / 2);
			String hash = idhash.substring(idhash.length() / 2);
			if (new BigInteger(new BigInteger(id).bitLength(), new Random(
					Long.parseLong(id))).add(new BigInteger("TopCoder", 36))
					.toString().endsWith(hash)) {
				return Integer.parseInt(id);
			} else {
				return 0;
			}

		} catch (Exception e) {
			return 0;
		}
	}
	
	/**
	 * Utility to create a Map as:
	 * Map<String, Object> = hash(	key1, value1,
	 * 								key2, value2,
	 * 								key3, value3,
	 * 								... );
	 * @param kvPairs
	 * @return
	 */
	public static Map<String, Object> hash(Object... kvPairs) {
		Map<String, Object> hash = new HashMap<String, Object>();
		for(int i=0; i<kvPairs.length; i+=2) {
			Object k = kvPairs[i];
			Object v = (i+1<kvPairs.length) ? kvPairs[i+1] : "";
			hash.put(k!=null?k.toString():"", v);
		}
		return hash;
	}
	
	/**
	 * Utility to convert TCID to a Long value. (= Long.parseLong(id.getId()))
	 * @param id
	 * @return
	 * @throws NumberFormatException
	 */
	public static Long toLongValue(TCID id) {
		if(id==null || id.getId()==null)
			return null;
		try {
			return Long.parseLong(id.getId());
		} catch (NumberFormatException e) {
			throw new NumberFormatException("Failed to convert TCID to long. error: " + e.getMessage());
		}
	}
	
	public static abstract class TokenExtractor {
		protected Set<String> ignoreTokens;
		public TokenExtractor(Set<String> ignoreWords) {
			this.ignoreTokens = ignoreWords;
		}
		public abstract Set<String> extractTokens(String handle);
	}
	
	/**
	 * extracts tokens as: 
	 * "12handle34" ->
	 * 	["12handle34", "12handle3", "12handle", "2handle34", "2handle3", "2handle", "handle34", "handle3", "handle"] 
	 */
	public static class NumberTrimmingTokenExtractor extends TokenExtractor {
		
		public NumberTrimmingTokenExtractor(Set<String> ignoreTokens) {
			super(ignoreTokens);
		}
		@Override
		public Set<String> extractTokens(String handle) {
			Set<String> extractedTokens = new LinkedHashSet<String>();
			if(handle==null || handle.length()==0)
				return extractedTokens;
			
			// find heading and trailing digits count
			int head = 0;
			while (head < handle.length() && Character.isDigit(handle.charAt(head))) {
				head++;
			}
			if (head >= handle.length()) {
				head = handle.length() - 1;
			}
			int tail = handle.length() - 1;
			while (tail >= 0 && Character.isDigit(handle.charAt(tail))) {
				tail--;
			}
			if (tail < 0) {
				tail = 0;
			}
			// remove all possible heading and trailing digits
			for (int i = 0; i <= head; i++) {
				for (int j = handle.length(); j > tail && j > i; j--) {
					String token = handle.substring(i, j);
					if(token.length()>0 && !ignoreTokens.contains(token)) {
						extractedTokens.add(token);
						ignoreTokens.add(token);
					}
				}
			}
			return extractedTokens;
		}
	}
	
	/**
	 * extracts tokens from the given handle by regex patterns.
	 */
	public static class RegexTokenExtractor extends TokenExtractor {
		protected Pattern[] patterns;
		public RegexTokenExtractor(Pattern[] patterns, Set<String> ignoreTokens) {
			super(ignoreTokens);
			this.patterns = patterns;
		}
		@Override
		public Set<String> extractTokens(String handle) {
			Set<String> extractedTokens = new LinkedHashSet<String>();
			if(handle==null || handle.length()==0)
				return extractedTokens;
			
			// breaking the handle into tokens by the patterns
			for(int i=0; i<patterns.length; i++) {
				Matcher m = patterns[i].matcher(handle);
				if (m.matches()) {
					String token = m.group(1);
					if (!ignoreTokens.contains(token) && token.length() > 0) {
						extractedTokens.add(token);
						ignoreTokens.add(token);
					}
				}
			}
			return extractedTokens;
		}
	}
	
	@SuppressWarnings("unchecked")
	public static Map<String, Object> parseJWTClaims(String token) throws Exception {
		if (token==null || token.length()==0)
			throw new IllegalArgumentException("token must be specified.");
		
		String[] pieces = token.split("\\.");
		if (pieces.length != 3)
			throw new IllegalArgumentException("Wrong number of segments in jwt: " + pieces.length);
		
		ObjectMapper mapper = new ObjectMapper();
		String jsonString = new String(Base64.decodeBase64(pieces[1]), "UTF-8");
		JsonNode jwtClaim = mapper.readValue(jsonString, JsonNode.class);
		return mapper.treeToValue(jwtClaim, Map.class);
	}
	
	/**
     * Parse jwt header
     *
     * @param token the token to use
     * @throws Exception if any error occurs
     * @return the Map<String,Object> result contains the header info
     */
    public static Map<String, Object> parseJWTHeader(String token) throws Exception {
        if (token==null || token.length()==0)
            throw new IllegalArgumentException("token must be specified.");
        
        String[] pieces = token.split("\\.");
        if (pieces.length != 3) {
            throw new IllegalArgumentException("Wrong number of segments in jwt: " + pieces.length);
        }
            
        ObjectMapper mapper = new ObjectMapper();
        String jsonString = new String(Base64.decodeBase64(pieces[0]), "UTF-8");
        JsonNode jwtHeader = mapper.readValue(jsonString, JsonNode.class);
        return mapper.treeToValue(jwtHeader, Map.class);
    }
	
	public static boolean isEmail(String handleOrEmail) {
		if(isBlank(handleOrEmail))
			throw new IllegalArgumentException("handleOrEmail must be specified.");
		return handleOrEmail.contains("@");
	}
	

	public static boolean isEmpty(String str) {
		return StringUtils.isEmpty(str);
	}
	
	public static boolean isBlank(String str) {
		return StringUtils.isBlank(str);
	}

	/**
	 * Check string length.
	 * 
	 * @param str the string to check
	 * @param min the minimum length
	 * @param max the maximum length
	 * @return true if string length is within [min, max] scope, false otherwise
	 */
	public static boolean checkStringLength(String str, Integer min, Integer max) {
		int length = str == null ? 0 : str.length();
		if (min != null && length < min) {
			return false;
		}
		if (max != null && length > max) {
			return false;
		}
		return true;
	}
    
    /**
     * Check if the user has admin role.
     * @param user the user.
     * @return if the user admin role.
     */
	public static boolean hasAdminRole(AuthUser authUser) {
		if (authUser == null || authUser.getRoles() == null) {
			return false;
		}

		for (String role : AdminRoles) {
			if (authUser.getRoles().contains(role)) {
				return true;
			}
		}

		return false;
	}
    
    public static JWTToken extractJWT(String token, String domain, String secret) {
    	if(token==null)
    		throw new IllegalArgumentException("token must be specified.");
    	
        try {
        	JWTToken jwt = new JWTToken(token, secret, Utils.getValidIssuers());
			jwt.isValidIssuerFor(domain);
			return jwt;
		} catch (Exception e) {
			throw new APIRuntimeException(SC_UNAUTHORIZED, e.getMessage());
		}
    }
    
	public static String extractBearer(HttpServletRequest request) {
		String prefix = "bearer";
    	String header = request.getHeader(HttpHeaders.AUTHORIZATION);
    	if(header==null || header.trim().length()==0)
    		return null;
		final int space = header.indexOf(' ');
		if(space <= 0)
			return null;
		
		String method = header.substring(0, space);
		if(!prefix.equalsIgnoreCase(method))
			return null;
		
		return header.substring(space + 1);
	}

	public static String getFullURL(HttpServletRequest request) {
		StringBuffer requestURL = request.getRequestURL();
		// for mock testing
		if (requestURL == null) {
			return "";
		}

		String fullURL = requestURL.toString();
		String queryString = request.getQueryString();

		if (queryString != null) {
			fullURL = requestURL.append('?').append(queryString).toString();
		}

		String serverName = request.getServerName().toLowerCase();
		if (serverName != null && (serverName.contains("topcoder-dev.com") || serverName.contains("topcoder-qa.com") || serverName.contains("topcoder.com")) && fullURL.startsWith("http://")) {
			fullURL = "https" +  fullURL.substring(4);
		}

		return fullURL;
	}

	public static void checkAccess(AuthUser authUser, String[] allowedScopes, String[] allowedRoles) {
		if (authUser == null) {
			throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_MANDATORY, "Authentication user"));
		}

		if (authUser.isMachine()) {
			if (allowedScopes == null || allowedScopes.length == 0) {
				return;
			}

			for (String allowedScope : allowedScopes) {
				if (authUser.getScope().contains(allowedScope)) {
					return;
				}
			}
		} else {
			if (allowedRoles == null || allowedRoles.length == 0) {
				return;
			}

			for (String role : allowedRoles) {
				if (authUser.getRoles() != null && authUser.getRoles().contains(role)) {
					return;
				}
			}
		}

		throw new APIRuntimeException(SC_FORBIDDEN, "Forbidden");
	}
}
