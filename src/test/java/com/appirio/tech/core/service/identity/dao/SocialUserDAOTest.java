package com.appirio.tech.core.service.identity.dao;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

import org.junit.Test;

import com.appirio.tech.core.service.identity.representation.UserProfile;
import com.appirio.tech.core.service.identity.representation.ProviderType;

public class SocialUserDAOTest {

	@Test
	public void testSocialIdExists() throws Exception {
		
		// data
		String existingId = "jdoe";
		Long existingUserId = 123456L;
		String unregisteredId = "jdoe2";
		
		// testee
		SocialUserDAO testee = mock(SocialUserDAO.class);
		when(testee.socialIdExists(anyString(), any(ProviderType.class))).thenCallRealMethod();
		when(testee.getUserIdBySocialId(existingId, ProviderType.FACEBOOK.id)).thenReturn(existingUserId); // exists
		when(testee.getUserIdBySocialId(unregisteredId, ProviderType.FACEBOOK.id)).thenReturn(null); // not exists
		
		// test - existing id
		boolean result = testee.socialIdExists(existingId, ProviderType.FACEBOOK);
		assertTrue(result);
		verify(testee).getUserIdBySocialId(existingId, ProviderType.FACEBOOK.id);
		
		// test - unregistered id
		result = testee.socialIdExists(unregisteredId, ProviderType.FACEBOOK);
		assertFalse(result);
		verify(testee).getUserIdBySocialId(unregisteredId, ProviderType.FACEBOOK.id);
	}
	
	@Test
	public void testFindUserIdByProfile_WithSocialUserId() throws Exception {
		// data
		UserProfile profile = new UserProfile();
		profile.setUserId("jdoe");
		profile.setProviderType(ProviderType.FACEBOOK.name);
		Long relatedUserId = 123456L;
		
		// testee
		SocialUserDAO testee = mock(SocialUserDAO.class);
		when(testee.findUserIdByProfile(any(UserProfile.class))).thenCallRealMethod();
		when(testee.getUserIdBySocialId(profile.getUserId(), ProviderType.FACEBOOK.id)).thenReturn(relatedUserId);
		
		// test - social account which has been registered
		Long result = testee.findUserIdByProfile(profile);
		
		// verify result
		assertNotNull(result);
		assertEquals(relatedUserId, result);
		// verify mock
		verify(testee).getUserIdBySocialId(profile.getUserId(), ProviderType.FACEBOOK.id);
		verify(testee, never()).updateSocialId(anyString(), anyLong()); // social user-id in database should not be updated.
	}
	
	@Test
	public void testFindUserIdByProfile_WithSocialEmail() throws Exception {
		// data
		UserProfile profile = new UserProfile();
		profile.setUserId("jdoe");
		profile.setEmail("jdoe@examples.com");
		profile.setEmailVerified(true);
		profile.setProviderType(ProviderType.FACEBOOK.name);
		Long relatedUserId = 123456L;
		
		// testee
		SocialUserDAO testee = mock(SocialUserDAO.class);
		when(testee.findUserIdByProfile(any(UserProfile.class))).thenCallRealMethod();
		when(testee.getUserIdBySocialId(profile.getUserId(), ProviderType.FACEBOOK.id)).thenReturn(null); // not found with social-id
		when(testee.getUserIdBySocialEmail(profile.getEmail(), profile.isEmailVerified(), ProviderType.FACEBOOK.id)).thenReturn(relatedUserId); // found with social-email
		
		// test - social account which has been registered
		Long result = testee.findUserIdByProfile(profile);
		
		// verify result
		assertEquals(relatedUserId, result);
		// verify mock
		verify(testee).getUserIdBySocialId(profile.getUserId(), ProviderType.FACEBOOK.id);
		verify(testee).getUserIdBySocialEmail(profile.getEmail(), profile.isEmailVerified(), ProviderType.FACEBOOK.id);
		verify(testee).updateSocialId(profile.getUserId(), relatedUserId);
	}
	
	@Test
	public void testFindUserIdByProfile_WithSocialName() throws Exception {
		// data
		UserProfile profile = new UserProfile();
		profile.setUserId("jdoe");
		profile.setEmail(null); // email is null
		profile.setEmailVerified(false);
		profile.setName("john.doe"); // social name
		profile.setProviderType(ProviderType.FACEBOOK.name);
		Long relatedUserId = 123456L;
		
		// testee
		SocialUserDAO testee = mock(SocialUserDAO.class);
		when(testee.findUserIdByProfile(any(UserProfile.class))).thenCallRealMethod();
		when(testee.getUserIdBySocialId(profile.getUserId(), ProviderType.FACEBOOK.id)).thenReturn(null); // not found with social-id
		when(testee.getUserIdBySocialName(profile.getName(), ProviderType.FACEBOOK.id)).thenReturn(relatedUserId); // found with social-name
		
		// test - social account which has been registered
		Long result = testee.findUserIdByProfile(profile);
		
		// verify result
		assertEquals(relatedUserId, result);
		// verify mock
		verify(testee).getUserIdBySocialId(profile.getUserId(), ProviderType.FACEBOOK.id);
		verify(testee).getUserIdBySocialName(profile.getName(), ProviderType.FACEBOOK.id);
		verify(testee).updateSocialId(profile.getUserId(), relatedUserId);
	}
	
	@Test
	public void testFindUserIdByProfile_NullIfUserNotFound() throws Exception {
		// data
		UserProfile profile = new UserProfile();
		profile.setUserId("jdoe");
		profile.setEmail("jdoe@examples.com");
		profile.setEmailVerified(true);
		profile.setName("john.doe");
		profile.setProviderType(ProviderType.FACEBOOK.name);
		
		// testee
		SocialUserDAO testee = mock(SocialUserDAO.class);
		when(testee.findUserIdByProfile(any(UserProfile.class))).thenCallRealMethod();
		when(testee.getUserIdBySocialId(profile.getUserId(), ProviderType.FACEBOOK.id)).thenReturn(null); // not found with social-id
		when(testee.getUserIdBySocialEmail(profile.getEmail(), profile.isEmailVerified(), ProviderType.FACEBOOK.id)).thenReturn(null); // not found with social-email
		
		// test - social account which has been registered
		Long result = testee.findUserIdByProfile(profile);
		
		// verify result
		assertNull("findUserIdByProfile() should return null if any related user is not found in the system.", result);
		
		// verify mock
		verify(testee).getUserIdBySocialId(profile.getUserId(), ProviderType.FACEBOOK.id);
		verify(testee).getUserIdBySocialEmail(profile.getEmail(), profile.isEmailVerified(), ProviderType.FACEBOOK.id);
		verify(testee, never()).updateSocialId(anyString(), anyLong());
	}
}
