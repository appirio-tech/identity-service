package com.appirio.tech.core.service.identity.representation;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Map;

import org.junit.Test;

import com.appirio.tech.core.service.identity.util.Utils;

public class UserProfileTest {

	@Test
	public void testGetProviderTypeEnum() {
		
		UserProfile profile = new UserProfile();
		profile.setProviderType("facebook");
		ProviderType type = profile.getProviderTypeEnum();
		assertEquals(ProviderType.FACEBOOK, type);
		
		ProviderType[] types = ProviderType.values();
		// assigning provider by name
		for(int i=0; i<types.length; i++) {
			profile.setProviderType(types[i].name);
			assertEquals(types[i], profile.getProviderTypeEnum());
		}
		// assigning provider by id 
		for(int i=0; i<types.length; i++) {
			profile.setProviderTypeId(types[i].id);
			assertEquals(types[i], profile.getProviderTypeEnum());
		}
	}
	
	@Test
	public void testGetLocalUserId() {
		
		UserProfile profile = new UserProfile();
		assertNull(profile.getLocalUserId());
		
		String userId = "USER-ID";
		profile.setUserId(userId);
		assertEquals(userId, profile.getLocalUserId());
		
		String userIdDecoratedWithProviderName = "provider|" + userId;
		profile.setUserId(userIdDecoratedWithProviderName);
		assertEquals(userId, profile.getLocalUserId());
		
		String userIdDecoratedWithProviderAndConnection = "provider|connection|" + userId;
		profile.setUserId(userIdDecoratedWithProviderAndConnection);
		assertEquals(userId, profile.getLocalUserId());
	}
	
	@Test
	public void testIsSocialAndIsEnterprise() {
		
		UserProfile profile = new UserProfile();
		assertFalse(profile.isSocial());
		assertFalse(profile.isEnterprise());
		
		ProviderType[] types = ProviderType.values();
		for(int i=0; i<types.length; i++) {
			profile.setProviderType(types[i].name);
			if(types[i].isSocial) {
				assertTrue(profile.isSocial());
			}
			if(types[i].isEnterprise) {
				assertTrue(profile.isEnterprise());
			}
		}
	}
	
	@Test
	public void testApplyJWTClaims_WithIdentities() {
		// data
		final String userId = "EXTERNAL-USER-ID";
		final String username = "jdoe";
		final String email = "jdoe@appirio.com";
		final boolean emailVerified = true;
		final ProviderType providerType = ProviderType.FACEBOOK;
		Map<String, Object> claims = createClaimWithIdentities(userId, username, email, emailVerified, providerType.name, providerType.name);
		
		// test
		testApplyJWTClaims_With(
				userId,
				username,
				email,
				emailVerified,
				providerType,
				claims);
	}
	
	@Test
	public void testApplyJWTClaims_WithAuth0CustomConnection() {
		// data
		final String userId = "EXTERNAL-USER-ID";
		final String username = "jdoe";
		final String email = "jdoe@appirio.com";
		final boolean emailVerified = true;
		final ProviderType providerType = ProviderType.AUTH0;
		final String connection = "TC-User-Database";
		Map<String, Object> claims = createClaimWithIdentities(userId, username, email, emailVerified,
				providerType.name, connection);
		
		// test
		testApplyJWTClaims_With(
				userId,
				username,
				email,
				emailVerified,
				providerType,
				claims);
	}

	@Test
	public void testApplyJWTClaims_WithAuth0CustomConnectionWhichIsUnsupported() {
		// data
		final String userId = "EXTERNAL-USER-ID";
		final String username = "jdoe";
		final String email = "jdoe@appirio.com";
		final boolean emailVerified = true;
		final ProviderType providerType = ProviderType.AUTH0;
		final String connection = "UNSUPPORTED-CONNECTION";
		Map<String, Object> claims = createClaimWithIdentities(userId, username, email, emailVerified,
				providerType.name, connection);
		
		// test
		UserProfile profile = new UserProfile();
		profile.applyJWTClaims(claims);

		assertNull(profile.getUserId());
		assertNull(profile.getProviderTypeEnum());
	}

	@Test
	public void testApplyJWTClaims_WithUserId() {
		// data
		final String userId = "EXTERNAL-USER-ID";
		final String username = "jdoe";
		final String email = "jdoe@appirio.com";
		final boolean emailVerified = true;
		final ProviderType providerType = ProviderType.FACEBOOK;
		Map<String, Object> claims = createClaimWithUserId(userId, username, email, emailVerified, providerType);
		
		// test
		testApplyJWTClaims_With(
				userId,
				username,
				email,
				emailVerified,
				providerType,
				claims);
	}
	
	@Test
	public void testApplyJWTClaims_WithOAuth2CustomConnection() {
		// data
		final String userId = "EXTERNAL-USER-ID";
		final String username = "jdoe";
		final String email = "jdoe@appirio.com";
		final boolean emailVerified = true;
		final ProviderType providerType = ProviderType.DRIBBBLE;
		final String compositeUserId = String.format("%s|%s", providerType.name, userId);
		Map<String, Object> claims = createClaimWithIdentities(
				compositeUserId, username, email, emailVerified, 
				"oauth2", providerType.name);
		
		// test
		testApplyJWTClaims_With(
				userId,
				username,
				email,
				emailVerified,
				providerType,
				claims);
	}

	protected void testApplyJWTClaims_With(
			final String expectedUserId,
			final String expectedUsername,
			final String expectedEmail,
			final boolean expectedEmailVerified,
			final ProviderType expectedProviderType,
			final Map<String, Object> claims) {
		
		UserProfile profile = new UserProfile();
		profile.applyJWTClaims(claims);
		
		assertEquals(expectedUserId, profile.getUserId());
		assertEquals(expectedUsername, profile.getName());
		assertEquals(expectedEmail, profile.getEmail());
		assertEquals(expectedEmailVerified, profile.isEmailVerified());
		assertEquals(expectedProviderType, profile.getProviderTypeEnum());
		assertEquals(expectedProviderType.isSocial, profile.isSocial());
		assertEquals(expectedProviderType.isEnterprise, profile.isEnterprise());
	}
	
	@SuppressWarnings("serial")
	protected Map<String, Object> createClaimWithIdentities(
			final String userId, final String username, final String email, final boolean emailVerified,
			final String provider, final String connection) {
		
		ProviderType providerType = ProviderType.getByName(provider);
		if(providerType==null)
			providerType = ProviderType.getByName(connection);
		assertNotNull(String.format("Unsupported provider for %s, %s", provider, connection), providerType);
		
		return Utils.hash(
			providerType.usernameField, username,
			"email", email,
			"email_verified", emailVerified,
			"identities", new ArrayList<Map<String, Object>>() {{
				add(Utils.hash(
					"provider", provider,
					"connection", connection,
					"user_id", userId
				));}}
			);
	}
	
	protected Map<String, Object> createClaimWithUserId(final String userId,
			final String username, final String email,
			final boolean emailVerified, final ProviderType providerType) {
		Map<String, Object> claims = Utils.hash(
			providerType.usernameField, username,
			"email", email,
			"email_verified", emailVerified,
			"user_id", providerType.name+"|"+userId
			);
		return claims;
	}
}
