package com.appirio.tech.core.service.identity.dao;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

import org.junit.Test;

import com.appirio.tech.core.service.identity.representation.ProviderType;
import com.appirio.tech.core.service.identity.representation.UserProfile;


/**
 * Test SSOUserDAO
 * 
 * <p>
 * Changes in the version 1.1 72h TC Identity Service API Enhancements v1.0
 * - add tests for updateSSOUser
 * </p>
 * 
 * @author TCCoder
 * @version 1.1
 *
 */
public class SSOUserDAOTest {

	// create test data(UserProfile)
	protected UserProfile createTestProfile() {
		UserProfile profile = new UserProfile();
		profile.setProviderType(ProviderType.SAMLP.name); // samlp
		profile.setProvider("samlp-connection");
		profile.setUserId("DUMMY-USER-ID");
		profile.setEmail("DUMMY-EMAIL");
		return profile;
	}
	
	@Test
	public void testFindUserIdByProfile_UserIsFoundByEmail() throws Exception {
		
		// data
		UserProfile profile = createTestProfile();
		
		// testee
		SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
		when(ssoUserDao.findUserIdByProfile(any(UserProfile.class))).thenCallRealMethod();
		
		// mock
		Long userId = 123456L;
		Long providerId = 1L;
		when(ssoUserDao.getSSOProviderIdByName(profile.getProvider())).thenReturn(providerId);
		when(ssoUserDao.getUserIdBySSOEmail(profile.getEmail(), providerId)).thenReturn(userId);
		
		// test
		Long result = ssoUserDao.findUserIdByProfile(profile);
		
		// verify result
		assertNotNull("SSOUserDAO#findUserIdByProfile(profile) should return a result.", result);
		assertEquals(userId, result);
		
		// verify mock
		verify(ssoUserDao).getSSOProviderIdByName(profile.getProvider());
		verify(ssoUserDao).getUserIdBySSOEmail(profile.getEmail(), providerId);
		// getUserIdBySSOUserId should not be invoked in this case.
		verify(ssoUserDao, never()).getUserIdBySSOUserId(anyString(), anyLong());
	}

	@Test
	public void testFindUserIdByProfile_UserIsFoundByUserId() throws Exception {
		// data
		UserProfile profile = createTestProfile();
		
		// testee
		SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
		when(ssoUserDao.findUserIdByProfile(any(UserProfile.class))).thenCallRealMethod();
		
		// mock
		Long userId = 123456L;
		Long providerId = 1L;
		when(ssoUserDao.getSSOProviderIdByName(profile.getProvider())).thenReturn(providerId);
		when(ssoUserDao.getUserIdBySSOEmail(profile.getEmail(), providerId)).thenReturn(null);
		when(ssoUserDao.getUserIdBySSOUserId(profile.getUserId(), providerId)).thenReturn(userId);
		
		// test
		Long result = ssoUserDao.findUserIdByProfile(profile);
		
		// verify result
		assertNotNull("SSOUserDAO#findUserIdByProfile(profile) should return a result.", result);
		assertEquals(userId, result);
		
		// verify mock
		verify(ssoUserDao).getSSOProviderIdByName(profile.getProvider());
		verify(ssoUserDao).getUserIdBySSOEmail(profile.getEmail(), providerId);
		verify(ssoUserDao).getUserIdBySSOUserId(profile.getUserId(), providerId);
	}
	
	@Test
	public void testFindUserIdByProfile_Err_WhenProviderIsNotRegistered() throws Exception {
		// data
		UserProfile profile = createTestProfile();
		
		// testee
		SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
		when(ssoUserDao.findUserIdByProfile(any(UserProfile.class))).thenCallRealMethod();
		// mock
		when(ssoUserDao.getSSOProviderIdByName(profile.getProvider())).thenReturn(null); // provider is not registered.
		
		// test
		try {
			ssoUserDao.findUserIdByProfile(profile);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {}
		
		// verify mock
		verify(ssoUserDao).getSSOProviderIdByName(profile.getProvider());
	}
	
	@Test
	public void testCreateSSOUser() throws Exception {
		// data
		Long userId = 123456L;
		UserProfile profile = createTestProfile();
		
		// testee
		SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
		doCallRealMethod().when(ssoUserDao).createSSOUser(anyLong(), any(UserProfile.class));
		
		// mock
		long providerId = 1L;
		when(ssoUserDao.getSSOProviderIdByName(profile.getProvider())).thenReturn(providerId);
		
		// test
		ssoUserDao.createSSOUser(userId, profile);
		
		// verify
		verify(ssoUserDao).getSSOProviderIdByName(profile.getProvider());
		verify(ssoUserDao).createSSOUser(userId, providerId, profile);
	}
	
	@Test
	public void testCreateSSOUser_Err_WhenProfileWithoutBothUserIdAndEmail() throws Exception {
		// data
		Long userId = 123456L;
		UserProfile profile = createTestProfile();
		profile.setUserId(null);
		profile.setEmail(null);
		
		// testee
		SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
		doCallRealMethod().when(ssoUserDao).createSSOUser(anyLong(), any(UserProfile.class));
		
		// test
		try {
			ssoUserDao.createSSOUser(userId, profile);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {}

		// verify
		verify(ssoUserDao, never()).createSSOUser(anyLong(), anyLong(), any(UserProfile.class));
	}
	
	@Test
	public void testCreateSSOUser_Err_WhenProviderIsNotRegistered() throws Exception {
		// data
		Long userId = 123456L;
		UserProfile profile = createTestProfile();
		
		// testee
		SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
		doCallRealMethod().when(ssoUserDao).createSSOUser(anyLong(), any(UserProfile.class));
		
		// mock
		when(ssoUserDao.getSSOProviderIdByName(profile.getProvider())).thenReturn(null); // provider not registered
		
		// test
		try {
			ssoUserDao.createSSOUser(userId, profile);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {}

		// verify
		verify(ssoUserDao).getSSOProviderIdByName(profile.getProvider());
		verify(ssoUserDao, never()).createSSOUser(anyLong(), anyLong(), any(UserProfile.class));
	}
	
	/**
     * Test update sso user
     *
     * @throws Exception if any error occurs
     */
    @Test
    public void testUpdateSSOUser() throws Exception {
        // data
        Long userId = 123456L;
        UserProfile profile = createTestProfile();
        
        // testee
        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        doCallRealMethod().when(ssoUserDao).updateSSOUser(anyLong(), any(UserProfile.class));
        
        // mock
        long providerId = 1L;
        when(ssoUserDao.getSSOProviderIdByName(profile.getProvider())).thenReturn(providerId);
        
        // test
        ssoUserDao.updateSSOUser(userId, profile);
        
        // verify
        verify(ssoUserDao).getSSOProviderIdByName(profile.getProvider());
        verify(ssoUserDao).updateSSOUser(userId, providerId, profile);
    }
    
    /**
     * Test update sso user with error when profile without both user id and email
     *
     * @throws Exception if any error occurs
     */
    @Test
    public void testUpdateSSOUser_Err_WhenProfileWithoutBothUserIdAndEmail() throws Exception {
        // data
        Long userId = 123456L;
        UserProfile profile = createTestProfile();
        profile.setUserId(null);
        profile.setEmail(null);
        
        // testee
        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        doCallRealMethod().when(ssoUserDao).updateSSOUser(anyLong(), any(UserProfile.class));
        
        // test
        try {
            ssoUserDao.updateSSOUser(userId, profile);
            fail("IllegalArgumentException should be thrown in the previous step.");
        } catch (IllegalArgumentException e) {}

        // verify
        verify(ssoUserDao, never()).updateSSOUser(anyLong(), anyLong(), any(UserProfile.class));
    }
    
    @Test
    public void testUpdateSSOUser_Err_WhenProviderIsNotRegistered() throws Exception {
        // data
        Long userId = 123456L;
        UserProfile profile = createTestProfile();
        
        // testee
        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        doCallRealMethod().when(ssoUserDao).updateSSOUser(anyLong(), any(UserProfile.class));
        
        // mock
        when(ssoUserDao.getSSOProviderIdByName(profile.getProvider())).thenReturn(null); // provider not registered
        
        // test
        try {
            ssoUserDao.updateSSOUser(userId, profile);
            fail("IllegalArgumentException should be thrown in the previous step.");
        } catch (IllegalArgumentException e) {}

        // verify
        verify(ssoUserDao).getSSOProviderIdByName(profile.getProvider());
        verify(ssoUserDao, never()).updateSSOUser(anyLong(), anyLong(), any(UserProfile.class));
    }
}
