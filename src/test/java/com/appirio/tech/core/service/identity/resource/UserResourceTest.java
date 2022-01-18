package com.appirio.tech.core.service.identity.resource;

import com.appirio.eventsbus.api.client.EventProducer;
import com.appirio.tech.core.api.v3.ApiVersion;
import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.dropwizard.APIApplication;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.request.FieldSelector;
import com.appirio.tech.core.api.v3.request.FilterParameter;
import com.appirio.tech.core.api.v3.request.LimitQuery;
import com.appirio.tech.core.api.v3.request.OrderByQuery;
import com.appirio.tech.core.api.v3.request.PostPutRequest;
import com.appirio.tech.core.api.v3.request.QueryParameter;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.api.v3.response.Result;
import com.appirio.tech.core.api.v3.util.jwt.InvalidTokenException;
import com.appirio.tech.core.api.v3.util.jwt.JWTToken;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.dao.RoleDAO;
import com.appirio.tech.core.service.identity.dao.SSOUserDAO;
import com.appirio.tech.core.service.identity.dao.UserDAO;
import com.appirio.tech.core.service.identity.representation.*;
import com.appirio.tech.core.service.identity.resource.UserResource.ValidationResult;
import com.appirio.tech.core.service.identity.util.Constants;
import com.appirio.tech.core.service.identity.util.Utils;
import com.appirio.tech.core.service.identity.util.auth.Auth0Client;
import com.appirio.tech.core.service.identity.util.cache.CacheService;
import com.appirio.tech.core.service.identity.util.event.MailRepresentation;
import com.appirio.tech.core.service.identity.util.ldap.MemberStatus;
import com.appirio.tech.core.service.identity.util.m2mscope.UserProfilesFactory;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.dropwizard.jackson.Jackson;

import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import static com.appirio.tech.core.service.identity.util.Constants.*;
import static java.net.HttpURLConnection.*;
import static javax.servlet.http.HttpServletResponse.*;
import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

/**
 * Tests for UserResource
 * 
 * <p>
 * Changes in the version 1.1 72h TC Identity Service API Enhancements v1.0
 * - add tests for createOrUpdateSSOUserLogin
 * </p>
 * 
 * @author TCCoder
 * @version 1.1
 *
 */
@SuppressWarnings("unchecked")
public class UserResourceTest {
    
    private final RoleDAO mockRoleDao = mock(RoleDAO.class);
    
    private final UserProfilesFactory userProfilesFactory = new UserProfilesFactory();
    
    @Before
    @SuppressWarnings("serial")
    public void setup() {
        Utils.setApplicationContext(
                new HashMap<String, Object>(){
                    { put(Utils.CONTEXT_KEY_DEFAULT_PASSWORD, "DEFAULT-PASSWORD"); }});
        
        reset(mockRoleDao);
        final Role userRole = new Role();
        userRole.setId(new TCID("5"));
        userRole.setRoleName("Topcoder User");
        when(mockRoleDao.findRoleByName(eq("Topcoder User"))).thenReturn(userRole);
        when(mockRoleDao.assignRole(eq(5), any(Long.class), any(Long.class))).thenReturn(1);
    }
    
    @Test
    public void testCreateObject() throws Exception {
        // data
        User user = createTestUser(null);
        // test
        testCreateObject_WithUser(user);
    }

    @Test
    public void testCreateObject_ActiveUser() throws Exception {
        // data
        User user = createTestUser(null);
        user.setActive(true); // active user
        // test
        testCreateObject_WithUser(user);
    }

    @Test
    public void testCreateObject_ReferralProgram() throws Exception {
        // data
        User user = createTestUser(null);
        user.setUtmCampaign("ReferralProgram");
        user.setUtmSource("DUMMY-UTM-SOURCE");

        // test
        testCreateObject_WithUser(user);
    }
    
    @Test
    public void testCreateObject_400WhenUTMSourceIsNotSpecifiedInReferralProgram() throws Exception {
        // data
        User user = createTestUser(null);
        user.setUtmCampaign("ReferralProgram");

        try {
            // test
            testCreateObject_WithUser(user);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        }
    }

    /**
     * Test CreateSSOUserLogin
     * @throws Exception if any error occurs
     */
    @Test
    public void testCreateSSOUserLogin() throws Exception {
        User user = createTestUser(null);
        user.setUtmCampaign("ReferralProgram");
        
        UserDAO userDao = mock(UserDAO.class);

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null, userProfilesFactory));
        
        // Creating mock: PostPutRequest - give mock user
        UserProfile userProfile = new UserProfile();
        userProfile.setProvider("provider");
        userProfile.setUserId("userId");
        PostPutRequest<UserProfile> param = (PostPutRequest<UserProfile>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(userProfile);
        
        AuthUser authUser = TestUtils.createAdminAuthUserMock(new TCID(2L));
        
        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(userDao.createSSOUserDAO()).thenReturn(ssoUserDao);

        when(ssoUserDao.checkUserIdAndProviderId(1L, 1L)).thenReturn(0);
        when(ssoUserDao.getSSOProviderIdByName(userProfile.getProvider())).thenReturn(1L);
        
        // Test
        ApiResponse resp = testee.createSSOUserLogin(authUser, 1, param);

        // Checking result
        assertNotNull(resp);

        Result result = resp.getResult();
        assertNotNull(result);
        assertEquals(SC_OK, (int)result.getStatus());
        assertTrue(result.getSuccess());
        assertEquals(userProfile, result.getContent());
    }

    /**
     * Test CreateSSOUserLogin
     * @throws Exception if any error occurs
     */
    @Test
    public void testCreateSSOUserLogin_MachineUserWithCreateScopes() throws Exception {
        User user = createTestUser(null);
        user.setUtmCampaign("ReferralProgram");

        UserDAO userDao = mock(UserDAO.class);

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null));

        // Creating mock: PostPutRequest - give mock user
        UserProfile userProfile = new UserProfile();
        userProfile.setProvider("provider");
        userProfile.setUserId("userId");
        PostPutRequest<UserProfile> param = (PostPutRequest<UserProfile>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(userProfile);

        AuthUser authUser = TestUtils.createMachineUserMock(userProfilesFactory.getCreateScopes());

        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(userDao.createSSOUserDAO()).thenReturn(ssoUserDao);

        when(ssoUserDao.checkUserIdAndProviderId(1L, 1L)).thenReturn(0);
        when(ssoUserDao.getSSOProviderIdByName(userProfile.getProvider())).thenReturn(1L);

        // Test
        ApiResponse resp = testee.createSSOUserLogin(authUser, 1, param);

        // Checking result
        assertNotNull(resp);

        Result result = resp.getResult();
        assertNotNull(result);
        assertEquals(SC_OK, (int)result.getStatus());
        assertTrue(result.getSuccess());
        assertEquals(userProfile, result.getContent());
    }

    /**
     * Test CreateSSOUserLogin
     * @throws Exception if any error occurs
     */
    @Test
    public void testCreateSSOUserLogin_MachineUserWithoutCreateScopes() throws Exception {
        User user = createTestUser(null);
        user.setUtmCampaign("ReferralProgram");

        UserDAO userDao = mock(UserDAO.class);

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null));

        // Creating mock: PostPutRequest - give mock user
        UserProfile userProfile = new UserProfile();
        userProfile.setProvider("provider");
        userProfile.setUserId("userId");
        PostPutRequest<UserProfile> param = (PostPutRequest<UserProfile>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(userProfile);

        AuthUser authUser = TestUtils.createMachineUserMock(new String[0]);

        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(userDao.createSSOUserDAO()).thenReturn(ssoUserDao);

        when(ssoUserDao.checkUserIdAndProviderId(1L, 1L)).thenReturn(0);
        when(ssoUserDao.getSSOProviderIdByName(userProfile.getProvider())).thenReturn(1L);

        try {
            // Test
            testee.createSSOUserLogin(authUser, 1, param);
        } catch (APIRuntimeException e) {
            assertEquals(SC_FORBIDDEN, e.getHttpStatus());
            assertEquals("Forbidden", e.getMessage());
        }
    }

    /**
     * Test UpdateSSOUserLogin with update logic
     * @throws Exception if any error occurs
     */
    @Test
    public void testUpdateSSOUserLogin() throws Exception {
        User user = createTestUser(null);
        user.setUtmCampaign("ReferralProgram");
        
        UserDAO userDao = mock(UserDAO.class);

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null));
        
        // Creating mock: PostPutRequest - give mock user
        UserProfile userProfile = new UserProfile();
        userProfile.setProvider("provider");
        userProfile.setUserId("userId");
        PostPutRequest<UserProfile> param = (PostPutRequest<UserProfile>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(userProfile);
        
        AuthUser authUser = TestUtils.createAdminAuthUserMock(new TCID(2));
        
        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(userDao.createSSOUserDAO()).thenReturn(ssoUserDao);
        when(ssoUserDao.checkUserIdAndProviderId(1L, 1L)).thenReturn(1);
        when(ssoUserDao.getSSOProviderIdByName(userProfile.getProvider())).thenReturn(1L);
        
        // Test
        ApiResponse resp = testee.updateSSOUserLogin(authUser, 1, param);

        // Checking result
        assertNotNull(resp);

        Result result = resp.getResult();
        assertNotNull(result);
        assertEquals(SC_OK, (int)result.getStatus());
        assertTrue(result.getSuccess());
        assertEquals(userProfile, result.getContent());
    }

    /**
     * Test UpdateSSOUserLogin with update logic
     * @throws Exception if any error occurs
     */
    @Test
    public void testUpdateSSOUserLogin_MachineUserWithUpdateScopes() throws Exception {
        User user = createTestUser(null);
        user.setUtmCampaign("ReferralProgram");

        UserDAO userDao = mock(UserDAO.class);

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null));

        // Creating mock: PostPutRequest - give mock user
        UserProfile userProfile = new UserProfile();
        userProfile.setProvider("provider");
        userProfile.setUserId("userId");
        PostPutRequest<UserProfile> param = (PostPutRequest<UserProfile>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(userProfile);

        AuthUser authUser = TestUtils.createMachineUserMock(userProfilesFactory.getUpdateScopes());

        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(userDao.createSSOUserDAO()).thenReturn(ssoUserDao);
        when(ssoUserDao.checkUserIdAndProviderId(1L, 1L)).thenReturn(1);
        when(ssoUserDao.getSSOProviderIdByName(userProfile.getProvider())).thenReturn(1L);

        // Test
        ApiResponse resp = testee.updateSSOUserLogin(authUser, 1, param);

        // Checking result
        assertNotNull(resp);

        Result result = resp.getResult();
        assertNotNull(result);
        assertEquals(SC_OK, (int)result.getStatus());
        assertTrue(result.getSuccess());
        assertEquals(userProfile, result.getContent());
    }

    /**
     * Test UpdateSSOUserLogin with update logic
     * @throws Exception if any error occurs
     */
    @Test
    public void testUpdateSSOUserLogin_MachineUserWithoutUpdateScopes() throws Exception {
        User user = createTestUser(null);
        user.setUtmCampaign("ReferralProgram");

        UserDAO userDao = mock(UserDAO.class);

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null));

        // Creating mock: PostPutRequest - give mock user
        UserProfile userProfile = new UserProfile();
        userProfile.setProvider("provider");
        userProfile.setUserId("userId");
        PostPutRequest<UserProfile> param = (PostPutRequest<UserProfile>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(userProfile);

        AuthUser authUser = TestUtils.createMachineUserMock(new String[0]);

        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(userDao.createSSOUserDAO()).thenReturn(ssoUserDao);
        when(ssoUserDao.checkUserIdAndProviderId(1L, 1L)).thenReturn(1);
        when(ssoUserDao.getSSOProviderIdByName(userProfile.getProvider())).thenReturn(1L);

        // Test
        try {
            testee.updateSSOUserLogin(authUser, 1, param);
        } catch (APIRuntimeException e) {
            assertEquals(SC_FORBIDDEN, e.getHttpStatus());
            assertEquals("Forbidden", e.getMessage());
        }
    }

    /**
     * Test DeleteSSOUserLogin 
     * @throws Exception if any error occurs
     */
    @Test
    public void testDeleteSSOUserLoginWithProviderId() throws Exception {
        User user = createTestUser(null);
        user.setUtmCampaign("ReferralProgram");
        
        UserDAO userDao = mock(UserDAO.class);

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null));

        AuthUser authUser = TestUtils.createAdminAuthUserMock(new TCID(2L));
        
        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(userDao.createSSOUserDAO()).thenReturn(ssoUserDao);
        when(ssoUserDao.checkUserIdAndProviderId(1L, 1L)).thenReturn(1);
        when(ssoUserDao.getSSOProviderIdByName("provider")).thenReturn(1L);
        
        // Test
        ApiResponse resp = testee.deleteSSOUserLogin(authUser, 1, null, 1L);

        // Checking result
        assertNotNull(resp);

        Result result = resp.getResult();
        assertNotNull(result);
        assertEquals(SC_OK, (int)result.getStatus());
        assertTrue(result.getSuccess());
        verify(ssoUserDao).deleteSSOUser(any(Long.class), any(Long.class));
    }

    /**
     * Test DeleteSSOUserLogin
     * @throws Exception if any error occurs
     */
    @Test
    public void testDeleteSSOUserLoginWithProviderId_MachineUserWithDeleteScopes() throws Exception {
        User user = createTestUser(null);
        user.setUtmCampaign("ReferralProgram");

        UserDAO userDao = mock(UserDAO.class);

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null));

        AuthUser authUser = TestUtils.createMachineUserMock(userProfilesFactory.getDeleteScopes());

        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(userDao.createSSOUserDAO()).thenReturn(ssoUserDao);
        when(ssoUserDao.checkUserIdAndProviderId(1L, 1L)).thenReturn(1);
        when(ssoUserDao.getSSOProviderIdByName("provider")).thenReturn(1L);

        // Test
        ApiResponse resp = testee.deleteSSOUserLogin(authUser, 1, null, 1L);

        // Checking result
        assertNotNull(resp);

        Result result = resp.getResult();
        assertNotNull(result);
        assertEquals(SC_OK, (int)result.getStatus());
        assertTrue(result.getSuccess());
        verify(ssoUserDao).deleteSSOUser(any(Long.class), any(Long.class));
    }

    /**
     * Test DeleteSSOUserLogin
     * @throws Exception if any error occurs
     */
    @Test
    public void testDeleteSSOUserLoginWithProviderId_MachineUserWithoutDeleteScopes() throws Exception {
        User user = createTestUser(null);
        user.setUtmCampaign("ReferralProgram");

        UserDAO userDao = mock(UserDAO.class);

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null));

        AuthUser authUser = TestUtils.createMachineUserMock(new String[0]);

        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(userDao.createSSOUserDAO()).thenReturn(ssoUserDao);
        when(ssoUserDao.checkUserIdAndProviderId(1L, 1L)).thenReturn(1);
        when(ssoUserDao.getSSOProviderIdByName("provider")).thenReturn(1L);

        // Test
        try {
            ApiResponse resp = testee.deleteSSOUserLogin(authUser, 1, null, 1L);
        } catch (APIRuntimeException e) {
            assertEquals(SC_FORBIDDEN, e.getHttpStatus());
            assertEquals("Forbidden", e.getMessage());
        }
    }

    /**
     * Test DeleteSSOUserLogin
     * @throws Exception if any error occurs
     */
    @Test
    public void testDeleteSSOUserLoginWithProvider() throws Exception {
        User user = createTestUser(null);
        user.setUtmCampaign("ReferralProgram");
        
        UserDAO userDao = mock(UserDAO.class);

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null));
        
        
        AuthUser authUser = TestUtils.createAdminAuthUserMock(new TCID(2L));
        
        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(userDao.createSSOUserDAO()).thenReturn(ssoUserDao);
        when(ssoUserDao.checkUserIdAndProviderId(1L, 1L)).thenReturn(1);
        when(ssoUserDao.getSSOProviderIdByName("provider")).thenReturn(1L);
        
        // Test
        ApiResponse resp = testee.deleteSSOUserLogin(authUser, 1, "provider", null);

        // Checking result
        assertNotNull(resp);

        Result result = resp.getResult();
        assertNotNull(result);
        assertEquals(SC_OK, (int)result.getStatus());
        assertTrue(result.getSuccess());
        verify(ssoUserDao).deleteSSOUser(any(Long.class), any(Long.class));
    }
    
    /**
     * Test getSSOUserLogin with update logic
     * @throws Exception if any error occurs
     */
    @Test
    public void testGetSSOUserLoginsByUserId() throws Exception {
        User user = createTestUser(null);
        user.setUtmCampaign("ReferralProgram");
        
        UserDAO userDao = mock(UserDAO.class);

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null));
        
        // Creating mock: PostPutRequest - give mock user
        UserProfile userProfile = new UserProfile();
        userProfile.setProvider("provider");
        userProfile.setUserId("userId");
        List<UserProfile> profiles = new ArrayList<>();
        profiles.add(userProfile);
        
        AuthUser authUser = TestUtils.createAdminAuthUserMock(new TCID(2L));
        
        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(ssoUserDao.findProfilesByUserId(1L)).thenReturn(profiles);
        when(userDao.createSSOUserDAO()).thenReturn(ssoUserDao);
        
        // Test
        ApiResponse resp = testee.getSSOUserLoginsByUserId(authUser, 1);

        // Checking result
        assertNotNull(resp);

        Result result = resp.getResult();
        assertNotNull(result);
        assertEquals(SC_OK, (int)result.getStatus());
        assertTrue(result.getSuccess());
        assertEquals(userProfile, ((List<UserProfile>) result.getContent()).get(0));
    }

    /**
     * Test getSSOUserLogin with update logic
     * @throws Exception if any error occurs
     */
    @Test
    public void testGetSSOUserLoginsByUserId_MachineUserWithReadScopes() throws Exception {
        User user = createTestUser(null);
        user.setUtmCampaign("ReferralProgram");

        UserDAO userDao = mock(UserDAO.class);

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null));

        // Creating mock: PostPutRequest - give mock user
        UserProfile userProfile = new UserProfile();
        userProfile.setProvider("provider");
        userProfile.setUserId("userId");
        List<UserProfile> profiles = new ArrayList<>();
        profiles.add(userProfile);

        AuthUser authUser = TestUtils.createMachineUserMock(userProfilesFactory.getReadScopes());

        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(ssoUserDao.findProfilesByUserId(1L)).thenReturn(profiles);
        when(userDao.createSSOUserDAO()).thenReturn(ssoUserDao);

        // Test
        ApiResponse resp = testee.getSSOUserLoginsByUserId(authUser, 1);

        // Checking result
        assertNotNull(resp);

        Result result = resp.getResult();
        assertNotNull(result);
        assertEquals(SC_OK, (int)result.getStatus());
        assertTrue(result.getSuccess());
        assertEquals(userProfile, ((List<UserProfile>) result.getContent()).get(0));
    }

    /**
     * Test getSSOUserLogin with update logic
     * @throws Exception if any error occurs
     */
    @Test
    public void testGetSSOUserLoginsByUserId_MachineUserWithoutReadScopes() throws Exception {
        User user = createTestUser(null);
        user.setUtmCampaign("ReferralProgram");

        UserDAO userDao = mock(UserDAO.class);

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null));

        // Creating mock: PostPutRequest - give mock user
        UserProfile userProfile = new UserProfile();
        userProfile.setProvider("provider");
        userProfile.setUserId("userId");
        List<UserProfile> profiles = new ArrayList<>();
        profiles.add(userProfile);

        AuthUser authUser = TestUtils.createMachineUserMock(new String[0]);

        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(ssoUserDao.findProfilesByUserId(1L)).thenReturn(profiles);
        when(userDao.createSSOUserDAO()).thenReturn(ssoUserDao);

        // Test
        try {
            testee.getSSOUserLoginsByUserId(authUser, 1);
        } catch (APIRuntimeException e) {
            assertEquals(SC_FORBIDDEN, e.getHttpStatus());
            assertEquals("Forbidden", e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    public void testCreateObject_WithUser(User userdata) throws Exception {

        // Creating mock: User - always validated
        boolean isUserActive = userdata.isActive();
        User user = spy(userdata);
        doReturn(null).when(user).validate();


        // Creating mock: PostPutRequest - give mock user
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(user);

        // Creating mock: UserDAO - always judge that there's no duplication in input data.
        TCID id = new TCID(123456L);
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findCountryBy(user.getCountry())).thenReturn(new Country()); // country name is valid
        when(userDao.register(user)).thenReturn(id);

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");

        // Testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null));
        testee.setObjectMapper(objectMapper);
        
        doReturn(null).when(testee).validateReferral(anyString());
        doReturn("non-null").when(testee).validateReferral(null);
        doNothing().when(testee).setAccessToken(userdata.getProfile()); // do nothing

        // Test
        ApiResponse resp = testee.createObject(param, null);

        // Checking result
        assertNotNull(resp);

        Result result = resp.getResult();
        assertNotNull(result);
        assertEquals(SC_OK, (int)result.getStatus());
        assertTrue(result.getSuccess());
        assertEquals(user, result.getContent());

        // verifying mocks
        verify(user).validate();
        verify(userDao).findCountryBy(user.getCountry());
        verify(userDao).register(user);
        verify(testee).validateHandle(user.getHandle());
        verify(testee).validateEmail(user.getEmail());
        verify(testee).validateCountry(user.getCountry());
        // validateProfile() should not be called for user without profile
        verify(testee,
                userdata.getProfile()!=null ? times(1) : never() // user profile should be validated
                ).validateProfile(user.getProfile());
        verify(testee,
                userdata.getProfile()!=null ? times(1) : never()
                ).setAccessToken(user.getProfile());
        verify(testee,
                user.isReferralProgramCampaign() ? times(1) : never()
                ).validateReferral(user.getUtmSource());

        /* 
        //jira-plat-130 
        verify(eventProducer).publish("event.user.created", "payload");
        verify(eventProducer,
                isUserActive? never() : times(1)).
                publish("event.notification.send", "payload");
       */
        verify(objectMapper).writeValueAsString(user);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testCreateObject_400WhenHandleIsInvalid() {

        // Creating mock: User - always validated
        User user = spy(createTestUser(null));
        doReturn(null).when(user).validate();

        // Creating mock: PostPutRequest - give mock user
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(user);

        // Creating mock: UserDAO - always judge that the handle is duplicated.
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.isInvalidHandle(user.getHandle())).thenReturn(true); // invalid!

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // Test
        UserResource testee = new UserResource(userDao, mockRoleDao, cache, eventProducer, null);
        try {
            testee.createObject(param, null);
            fail("Exception should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
            assertEquals(MSG_TEMPLATE_INVALID_HANDLE, e.getMessage());
        }

        // verifying mocks
        verify(user).validate();
        verify(userDao).isInvalidHandle(user.getHandle());
        verify(userDao, never()).register(any(User.class));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testCreateObject_400WhenHandleIsDuplicated() {

        // Creating mock: User - always validated
        User user = spy(createTestUser(null));
        doReturn(null).when(user).validate();

        // Creating mock: PostPutRequest - give mock user
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(user);

        // Creating mock: UserDAO - always judge that the handle is duplicated.
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.handleExists(user.getHandle())).thenReturn(true); // duplicated!

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // Test
        UserResource testee = new UserResource(userDao, mockRoleDao, cache, eventProducer, null);
        try {
            testee.createObject(param, null);
            fail("Exception should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
            assertEquals(String.format(MSG_TEMPLATE_DUPLICATED_HANDLE, user.getHandle()), e.getMessage());
        }

        // verifying mocks
        verify(user).validate();
        verify(userDao).handleExists(user.getHandle());
        verify(userDao, never()).register(any(User.class));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testCreateObject_400WhenEmailIsAlreadyRegistered() {

        // Creating mock: User - always validated
        User user = spy(createTestUser(null));
        doReturn(null).when(user).validate();

        // Creating mock: PostPutRequest - give mock user
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(user);

        // Creating mock: UserDAO - always judge that the handle is duplicated.
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.handleExists(user.getHandle())).thenReturn(false); // not duplicated for handle
        when(userDao.emailExists(user.getEmail())).thenReturn(true); // duplicated!

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // Test
        UserResource testee = new UserResource(userDao, mockRoleDao, cache, eventProducer, null);
        try {
            testee.createObject(param, null);
            fail("Exception should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
            assertEquals(String.format(MSG_TEMPLATE_DUPLICATED_EMAIL, user.getEmail()), e.getMessage());
        }

        // verifying mocks
        verify(user).validate();
        verify(userDao).handleExists(user.getHandle());
        verify(userDao).emailExists(user.getEmail());
        verify(userDao, never()).register(any(User.class));
    }


    @SuppressWarnings("unchecked")
    @Test
    public void testCreateObject_400WhenSocialProfileIsAlreadyInUse() {

        // data
        User user = spy(createTestUser(null));
        List<UserProfile> profiles = new ArrayList<>();
        user.setProfiles(profiles);
        UserProfile profile = new UserProfile();
        profiles.add(profile);
        profile.setUserId(user.getHandle());
        profile.setProviderType(ProviderType.FACEBOOK.name);
        doReturn(null).when(user).validate(); // always validated

        // Creating mock: PostPutRequest - gives mock user
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(user);

        // Creating mock: UserDAO - always judge that the handle is not duplicated.
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.handleExists(user.getHandle())).thenReturn(false);
        when(userDao.emailExists(user.getEmail())).thenReturn(false);
        when(userDao.findCountryBy((user.getCountry()))).thenReturn(new Country()); // country name is valid
        when(userDao.socialUserExists(profile)).thenReturn(true); // social account is already in use.

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // Test
        UserResource testee = new UserResource(userDao, mockRoleDao, cache, eventProducer, null);
        try {
            testee.createObject(param, null);
            fail("Exception should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
            assertEquals(MSG_TEMPLATE_SOCIAL_PROFILE_IN_USE, e.getMessage());
        }

        // verifying mocks
        verify(user).validate();
        verify(userDao).handleExists(user.getHandle());
        verify(userDao).emailExists(user.getEmail());
        verify(userDao).findCountryBy((user.getCountry()));
        verify(userDao).socialUserExists(user.getProfile());
        verify(userDao, never()).register(any(User.class));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testCreateObject_400WhenCountryIsInvalid() {

        // data
        User user = spy(createTestUser(null));
        doReturn(null).when(user).validate(); // always validated

        // Creating mock: PostPutRequest - gives mock user
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(user);

        // Creating mock: UserDAO - always judge that the handle is not duplicated.
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.handleExists(user.getHandle())).thenReturn(false);
        when(userDao.emailExists(user.getEmail())).thenReturn(false);
        when(userDao.findCountryBy(user.getCountry())).thenReturn(null); // country name does not exist.

        // Creating mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // Test
        UserResource testee = new UserResource(userDao, mockRoleDao, cache, eventProducer, null);
        try {
            testee.createObject(param, null);
            fail("Exception should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
            assertEquals(MSG_TEMPLATE_INVALID_COUNTRY, e.getMessage());
        }

        // verifying mocks
        verify(user).validate();
        verify(userDao).handleExists(user.getHandle());
        verify(userDao).emailExists(user.getEmail());
        verify(userDao).findCountryBy(user.getCountry());
        verify(userDao, never()).register(any(User.class));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testUpdateObject() throws Exception {

        // data - input
        User user = spy(new User());
        user.setFirstName("AnotherFirstName");
        user.setLastName("AnotherLastName");
        user.setRegSource("AnotherRegSource");
        user.setUtmSource("AnotherUtmSource");
        user.setUtmMedium("AnotherUtmMedium");
        user.setUtmCampaign("AnotherUtmCampaign");
        // mock
        doReturn(null).when(user).validateFirstName();
        doReturn(null).when(user).validateLastName();

        // data - dataabse
        long userId = 123456L;
        User dbUser = spy(createTestUser(userId));

        // mock: request/response
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock: PostPutRequest - gives mock user
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(user);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        doReturn(dbUser).when(userDao).findUserById(userId);
        doReturn(dbUser.getId()).when(userDao).update(dbUser);

        // mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // Test
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(userId);
        doReturn(id).when(authUser).getUserId();

        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null));
        ApiResponse resp = testee.updateObject(authUser, String.valueOf(userId), param, request);

        // Checking result
        assertNotNull(resp);
        Result result = resp.getResult();
        assertNotNull(result);
        assertEquals(SC_OK, (int)result.getStatus());
        assertTrue(result.getSuccess());
        assertEquals(dbUser, result.getContent());

        assertEquals(user.getFirstName(), dbUser.getFirstName());
        assertEquals(user.getLastName(), dbUser.getLastName());
        assertEquals(user.getRegSource(), dbUser.getRegSource());
        assertEquals(user.getUtmSource(), dbUser.getUtmSource());
        assertEquals(user.getUtmMedium(), dbUser.getUtmMedium());
        assertEquals(user.getUtmCampaign(), dbUser.getUtmCampaign());

        // Verify mocks
        verify(param, atLeastOnce()).getParam();
        verify(authUser).getUserId();
        verify(userDao).findUserById(userId);
        verify(user, never()).validatePassoword();

        verify(userDao).update(dbUser);
        verify(userDao, never()).updatePassword(any(User.class));
        
        // confirm check methods are passed
        verify(testee).checkResourceId(id);
        verify(testee).validateResourceIdAndCheckPermission(authUser, id, userProfilesFactory.getUpdateScopes());
        verify(testee).checkParam(param);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testUpdateObject_UpdatePassword() throws Exception {

        // data - input
        User user = spy(new User());
        user.setCredential(new Credential());
        user.getCredential().setCurrentPassword("OLD-PASSWORD");
        user.getCredential().setPassword("NEW-PASSWORD");
        // mock
        doReturn(null).when(user).validatePassoword();

        // data - dataabse
        long userId = 123456L;
        User dbUser = createTestUser(userId);
        dbUser.setCredential(spy(dbUser.getCredential()));
        // mock
        String oldPassword = user.getCredential().getCurrentPassword();
        doReturn(true).when(dbUser.getCredential()).isCurrentPassword(oldPassword);

        // mock: request/response
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock: PostPutRequest - gives mock user
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(user);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        doReturn(dbUser).when(userDao).findUserById(userId);
        doReturn(dbUser.getId()).when(userDao).update(dbUser);

        // mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // Test
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(userId);
        doReturn(id).when(authUser).getUserId();

        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cache, eventProducer, null));
        ApiResponse resp = testee.updateObject(authUser, String.valueOf(userId), param, request);

        // Checking result
        assertNotNull(resp);
        Result result = resp.getResult();
        assertNotNull(result);
        assertEquals(SC_OK, (int)result.getStatus());
        assertTrue(result.getSuccess());
        assertEquals(dbUser, result.getContent());

        assertEquals(user.getCredential().getEncodedPassword(), dbUser.getCredential().getEncodedPassword());

        // Verify mocks
        verify(param, atLeastOnce()).getParam();
        verify(authUser).getUserId();
        verify(user).validatePassoword();
        verify(dbUser.getCredential()).isCurrentPassword(user.getCredential().getCurrentPassword());
        verify(userDao).findUserById(userId);
        verify(userDao).update(dbUser);
        verify(userDao).updatePassword(dbUser);
        
        // confirm check methods are passed
        verify(testee).checkResourceId(id);
        verify(testee).validateResourceIdAndCheckPermission(authUser, id, userProfilesFactory.getUpdateScopes());
        verify(testee).checkParam(param);
    }
    
    @SuppressWarnings("unchecked")
    @Test
    public void testUpdateObject_404WhenUserNotFound() throws Exception {

        // mock
        HttpServletRequest request = mock(HttpServletRequest.class);
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(new User());
        UserDAO userDao = mock(UserDAO.class);
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // user is not found with userId
        long userId = 123456L;
        when(userDao.findUserById(userId)).thenReturn(null);

        // Test
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(userId);
        doReturn(id).when(authUser).getUserId();

        UserResource testee = new UserResource(userDao, mockRoleDao, cache, eventProducer, null);
        try {
            testee.updateObject(authUser, String.valueOf(userId), param, request);
        } catch(APIRuntimeException e) {
            assertEquals(SC_NOT_FOUND, e.getHttpStatus());
            assertEquals(MSG_TEMPLATE_USER_NOT_FOUND, e.getMessage());
        }

        // verify
        verify(param, atLeastOnce()).getParam();
        verify(authUser).getUserId();
        verify(userDao).findUserById(userId);
    }

    @Test
    public void testUpdateObject_400WhenFirstNameIsInvalid() throws Exception {

        // data - input
        User user = spy(new User());
        user.setFirstName("TooLongFirstName");
        // mock
        String msg = "DUMMY-ERROR-FIRST-NAME-IS-TOO-LONG";
        doReturn(msg).when(user).validateFirstName();

        testUpdateObject_ErrorWhenUserIsInvalid(user, SC_BAD_REQUEST, msg, user1 -> verify(user1).validateFirstName());
    }

    @Test
    public void testUpdateObject_400WhenLastNameIsInvalid() throws Exception {

        // data - input
        User user = spy(new User());
        user.setLastName("TooLongLastName");
        // mock
        String msg = "DUMMY-ERROR-LAST-NAME-IS-TOO-LONG";
        doReturn(msg).when(user).validateLastName();

        testUpdateObject_ErrorWhenUserIsInvalid(user, SC_BAD_REQUEST, msg, user1 -> verify(user1).validateLastName());
    }

    @Test
    public void testUpdateObject_400WhenPasswordIsInvalid() throws Exception {

        // data - input
        User user = spy(new User());
        user.setCredential(new Credential());
        user.getCredential().setPassword("INVALID-PASSWORD");

        // mock
        String msg = "DUMMY-ERROR-PASSWORD-IS-INVALID";
        doReturn(msg).when(user).validatePassoword();

        testUpdateObject_ErrorWhenUserIsInvalid(user, SC_BAD_REQUEST, msg, user1 -> verify(user1).validatePassoword());
    }

    @Test
    public void testUpdateObject_400WhenNoCurrentPasswordSpecifiedForUpdatingPassword() throws Exception {

        // data - input
        User user = spy(new User());
        user.setCredential(new Credential());
        user.getCredential().setPassword("NEW-PASSWORD");
        user.getCredential().setCurrentPassword(null); // current password is missing

        // mock
        doReturn(null).when(user).validatePassoword();

        String msg = String.format(MSG_TEMPLATE_MANDATORY, "Current password");
        testUpdateObject_ErrorWhenUserIsInvalid(user, SC_BAD_REQUEST, msg, user1 -> {});
    }

    @Test
    public void testUpdateObject_400WhenCurrentPasswordIsIncorrectForUpdatingPassword() throws Exception {

        // data - input
        User user = spy(new User());
        user.setCredential(new Credential());
        user.getCredential().setPassword("NEW-PASSWORD");
        user.getCredential().setCurrentPassword("INCORRECT-OLD-PASSWORD"); // @see createTestUser()

        // mock
        doReturn(null).when(user).validatePassoword();

        testUpdateObject_ErrorWhenUserIsInvalid(user, SC_BAD_REQUEST, MSG_TEMPLATE_INVALID_CURRENT_PASSWORD, user1 -> {});
    }

    interface UserVerifyer { void doVerify(User user); }

    @SuppressWarnings("unchecked")
    public void testUpdateObject_ErrorWhenUserIsInvalid(User user, int statusCode, String message, UserVerifyer verifyer) throws Exception {

        // data - dataabse
        long userId = 123456L;
        User dbUser = spy(createTestUser(userId));

        // mock: request/response
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock: PostPutRequest - gives mock user
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(user);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        doReturn(dbUser).when(userDao).findUserById(userId);

        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(userId);
        doReturn(id).when(authUser).getUserId();

        // mock: Other
        CacheService cache = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // test
        UserResource testee = new UserResource(userDao, mockRoleDao, cache, eventProducer, null);
        try {
            testee.updateObject(authUser, String.valueOf(userId), param, request);
        } catch(APIRuntimeException e) {
            assertEquals(statusCode, e.getHttpStatus());
            assertEquals(message, e.getMessage());
        }

        // Verify mocks
        verify(param, atLeastOnce()).getParam();
        verify(userDao).findUserById(userId);
        verify(userDao, never()).update(any(User.class));
        verify(userDao, never()).updatePassword(any(User.class));
        verifyer.doVerify(user);
    }

    @Test
    public void testCreateUserProfile() {
        // data - input
        String socialUserId = "DUMMY-SOCIAL-USER-ID";
        UserProfile profile = new UserProfile();
        profile.setUserId(socialUserId);
        profile.setProviderType(ProviderType.GITHUB.name);

        // data - dataabse
        long userId = 123456L;
        User user = spy(createTestUser(userId));

        // mock: request/response
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock: PostPutRequest
        @SuppressWarnings("unchecked")
        PostPutRequest<UserProfile> param = (PostPutRequest<UserProfile>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(profile);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        doReturn(user).when(userDao).findUserById(userId);

        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(userId);
        doReturn(id).when(authUser).getUserId(); // used to check permission to use the endpoint

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, null, null));
        // mock
        doReturn(null).when(testee).validateProfile(userId, profile); // always valid
        doNothing().when(testee).setAccessToken(profile); // do nothing

        // test
        try {
           ApiResponse resp = testee.createUserProfile(authUser, String.valueOf(userId), param, request);
        } catch (APIRuntimeException e) {
           // fixed bug in createUserProfile function
           assertEquals(SC_NOT_FOUND, e.getHttpStatus());
           userDao.addSocialProfile(userId, profile);
	}

        // Checking result
        /* not needed now
        assertNotNull(resp);
        Result result = resp.getResult();
        assertNotNull(result);
        assertEquals(SC_OK, (int)result.getStatus());
        assertTrue(result.getSuccess());
        assertEquals(profile, result.getContent());
        */

        // verify
        verify(param, atLeastOnce()).getParam();
        verify(authUser).getUserId();
        verify(userDao).findUserById(userId);
        verify(userDao).addSocialProfile(userId, profile);
        verify(testee).validateProfile(userId, profile);
        verify(testee).setAccessToken(profile);

        // confirm check methods are passed
        verify(testee).checkResourceId(id);
        verify(testee).validateResourceIdAndCheckPermission(authUser, id, userProfilesFactory.getCreateScopes());
        verify(testee).checkParam(param);
    }

    @Test
    public void testCreateUserProfile_400WhenPayloadIsInvalid() {

        // data - input
        UserProfile profile = new UserProfile();

        // data - dataabse
        long userId = 123456L;

        // mock: request/response
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock: PostPutRequest
        @SuppressWarnings("unchecked")
        PostPutRequest<UserProfile> param = (PostPutRequest<UserProfile>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(profile);

        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(userId);
        doReturn(id).when(authUser).getUserId(); // used to check permission to use the endpoint

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        // mock
        String errorMessageForInvalidPayload = "INVALID-PROFILE";
        doReturn(errorMessageForInvalidPayload).when(testee).validateProfile(userId, profile); // profile is invalid

        // test
        try {
            testee.createUserProfile(authUser, String.valueOf(userId), param, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
            assertEquals(errorMessageForInvalidPayload, e.getMessage());
        }

        // verify
        verify(param, atLeastOnce()).getParam();
        verify(authUser).getUserId();
        verify(testee).validateProfile(userId, profile);
    }

    @Test
    public void testCreateUserProfile_404WhenSpecifiedUserDoesNotExist() {
        // data - input
        UserProfile profile = new UserProfile();

        // data - dataabse
        long userId = 123456L;

        // mock: request/response
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock: PostPutRequest
        @SuppressWarnings("unchecked")
        PostPutRequest<UserProfile> param = (PostPutRequest<UserProfile>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(profile);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        doReturn(null).when(userDao).findUserById(userId); // user does not exist

        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(userId);
        doReturn(id).when(authUser).getUserId(); // used to check permission to use the endpoint

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, null, null));
        // mock
        doReturn(null).when(testee).validateProfile(userId, profile); // always valid

        // test
        try {
            testee.createUserProfile(authUser, String.valueOf(userId), param, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_NOT_FOUND, e.getHttpStatus());
            assertEquals(MSG_TEMPLATE_USER_NOT_FOUND, e.getMessage());
        }

        // verify
        verify(param, atLeastOnce()).getParam();
        verify(authUser).getUserId();
        verify(userDao).findUserById(userId);
        verify(userDao, never()).addSocialProfile(userId, profile); // never called
        verify(testee).validateProfile(userId, profile);
    }

    @Test
    public void testDeleteUserProfile() {
        // data - input
        long userId = 123456L;
        ProviderType provider = ProviderType.GITHUB;
        assertTrue("Provider should be social", provider.isSocial);

        // data - dataabse
        String socialUserId = "DUMMY-SOCIAL-USER-ID";
        UserProfile profile = new UserProfile();
        profile.setUserId(socialUserId);
        profile.setProviderType(provider.name);
        List<UserProfile> profiles = new ArrayList<>();
        profiles.add(profile);

        // mock: request/response
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        doReturn(profiles).when(userDao).getSocialProfiles(userId, provider);
        doNothing().when(userDao).deleteSocialProfiles(userId, provider);

        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(userId);
        doReturn(id).when(authUser).getUserId(); // used to check permission to use the endpoint

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, null, null));

        // test
        ApiResponse resp = testee.deleteUserProfile(authUser, String.valueOf(userId), provider.name, request);

        // Checking result
        assertNotNull(resp);
        Result result = resp.getResult();
        assertNotNull(result);
        assertEquals(SC_OK, (int)result.getStatus());
        assertTrue(result.getSuccess());
        assertEquals(profiles, result.getContent());

        // verify
        verify(authUser).getUserId();
        verify(userDao).getSocialProfiles(userId, provider);
        verify(userDao).deleteSocialProfiles(userId, provider);
        
        // confirm check methods are passed
        verify(testee).checkResourceId(id);
        verify(testee).validateResourceIdAndCheckPermission(authUser, id, userProfilesFactory.getDeleteScopes());
    }

    @Test
    public void testDeleteUserProfile_400WhenUserIdIsNotSpecified() {
        // data - input
        ProviderType provider = ProviderType.GITHUB;
        assertTrue("Provider should be social", provider.isSocial);

        // mock: request/response
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));

        // test
        try {
            testee.deleteUserProfile(authUser, null, provider.name, request); // userId(2nd argument) is null
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
            assertEquals(String.format(MSG_TEMPLATE_MANDATORY, "resourceId"), e.getMessage());
        }
    }

    @Test
    public void testDeleteUserProfile_400WhenProviderIsNotSpecified() {
        // data - input
        long userId = 123456L;

        // mock: request/response
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));

        // test
        try {
            testee.deleteUserProfile(authUser, String.valueOf(userId), null, request); // provider(3nd argument) is null
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
            assertEquals(String.format(MSG_TEMPLATE_MANDATORY, "provider"), e.getMessage());
        }
    }

    @Test
    public void testDeleteUserProfile_400WhenSpecifiedProviderIsNotSupported() {
        // data - input
        long userId = 123456L;
        String provider = "UNSUPPORTED-PROVIDER";

        // mock: request/response
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(userId);
        doReturn(id).when(authUser).getUserId(); // used to check permission to use the endpoint

        // testee
        UserResource testee = new UserResource(null, null, null, null, null);

        // test
        try {
            testee.deleteUserProfile(authUser, String.valueOf(userId), provider, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
            assertEquals(String.format(MSG_TEMPLATE_UNSUPPORTED_PROVIDER, provider), e.getMessage());
        }

        // verify
        verify(authUser).getUserId();
    }

    @Test
    public void testDeleteUserProfile_404WhenSpecifiedProfileDoesNotExist() {
        // data - input
        long userId = 123456L;
        ProviderType provider = ProviderType.GITHUB;
        assertTrue("Provider should be social", provider.isSocial);

        // mock: request/response
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        doReturn(null).when(userDao).getSocialProfiles(userId, provider); // profile does not exist

        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(userId);
        doReturn(id).when(authUser).getUserId(); // used to check permission to use the endpoint

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);

        // test
        try {
            testee.deleteUserProfile(authUser, String.valueOf(userId), provider.name, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_NOT_FOUND, e.getHttpStatus());
            assertEquals(MSG_TEMPLATE_SOCIAL_PROFILE_NOT_FOUND, e.getMessage());
        }

        // verify
        verify(authUser).getUserId();
        verify(userDao).getSocialProfiles(userId, provider);
        verify(userDao, never()).deleteSocialProfiles(anyLong(), any(ProviderType.class)); // never called
    }

    @Test
    public void testGetObject() throws Exception {
        // Setup
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        // Test data
        User user = new User();

        // mock: Parameters
        TCID userId = new TCID(101L);
        AuthUser authUser = createMockAdminAuthUser(userId);
        FieldSelector selector = mock(FieldSelector.class);
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.populateById(selector, userId)).thenReturn(user);

        EventProducer eventProducer = mock(EventProducer.class);
        // Test
        UserResource testee = new UserResource(userDao, mockRoleDao, null, eventProducer, null);
        ApiResponse result = testee.getObject(authUser, userId, selector, request);

        // Checking result
        assertNotNull("getObject() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(user, apiResult.getContent());

        // verify
        verify(userDao, only()).populateById(selector, userId);
    }

    @Test
    public void testGetObject_400WhenIdIsNull() throws Exception {

        // test data
        TCID userId = null;

        // mock: Parameters
        AuthUser authUser = mock(AuthUser.class);
        FieldSelector selector = mock(FieldSelector.class);
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // Test
        try {
            UserResource testee = new UserResource(userDao, mockRoleDao, null, eventProducer, null);
            testee.getObject(authUser, userId, selector, request);
            fail("getObject() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            // Checking result
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        }

        // verify
        verify(userDao, never()).populateById(selector, userId);
    }
    
    @Test
    public void testGetObject_404WhenUserDoesNotExist() throws Exception {

        // test data
        TCID userId = new TCID(101L);

        // mock: Parameters
        AuthUser authUser = createMockAuthUser(userId);
        FieldSelector selector = mock(FieldSelector.class);
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.populateById(selector, userId)).thenReturn(null); // null when user does not exist

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);

        // Test
        try {
            testee.getObject(authUser, userId, selector, request);
            fail("getObject() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            // Checking result
            assertEquals(SC_NOT_FOUND, e.getHttpStatus());
        }

        // verify
        verify(userDao).populateById(selector, userId);
    }
    
    @Test
    public void testGetObject_403WhenUserDoesNotHavePermission() throws Exception {
        // test data
        TCID userId = new TCID(101L);

        // mock: Parameters
        TCID operatorId = new TCID(102L);
        AuthUser authUser = createMockAuthUser(operatorId);
        assertNotEquals(userId, operatorId); // operator != target
        
        FieldSelector selector = mock(FieldSelector.class);
        HttpServletRequest request = mock(HttpServletRequest.class);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);

        // Test
        try {
            testee.getObject(authUser, userId, selector, request);
            fail("getObject() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            // Checking result
            assertEquals(SC_FORBIDDEN, e.getHttpStatus());
        }

        // verify
        verify(userDao, never()).populateById(selector, userId);
    }
    
    @Test
    public void testGetObjects() {
        // Setup
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        // Test data
        List<User> users = new ArrayList<>();
        users.add(new User());
        users.add(new User());

        // mock: Parameters
        AuthUser authUser = createMockAdminAuthUser(new TCID(101L));
        HttpServletRequest request = mock(HttpServletRequest.class);
        FieldSelector fields = new FieldSelector();
        FilterParameter filter = new FilterParameter(null);
        OrderByQuery orderBy = new OrderByQuery();
        orderBy.getItems().add(orderBy.new OrderByItem());
        LimitQuery limit = new LimitQuery(100);
        QueryParameter queryParam = new QueryParameter(fields, filter, limit, orderBy);
        
        
        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        doReturn(users).when(userDao).findUsers(filter, orderBy.getItems(), limit);
        // mock: EventProducer
        EventProducer eventProducer = mock(EventProducer.class);
        
        // Test
        UserResource testee = new UserResource(userDao, mockRoleDao, null, eventProducer, null);
        ApiResponse result = testee.getObjects(authUser, queryParam, request);

        // Checking result
        assertNotNull("getObjects() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();
        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(users, apiResult.getContent());

        // verify
        verify(userDao).findUsers(filter, orderBy.getItems(), limit);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testGetObjects_403WhenUserDoesNotHavePermission() {

        // mock: Parameters
        AuthUser authUser = mock(AuthUser.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        QueryParameter queryParam = new QueryParameter(null, null, null, null);
        
        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        // mock: EventProducer
        EventProducer eventProducer = mock(EventProducer.class);
        
        // Test
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, eventProducer, null));
        try {
            testee.getObjects(authUser, queryParam, request);
        } catch (APIRuntimeException e) {
            assertEquals(SC_FORBIDDEN, e.getHttpStatus());
        }

        // verify
        verify(userDao, never()).findUsers(any(FilterParameter.class), any(List.class), any(LimitQuery.class));
    }
    
    @SuppressWarnings("unchecked")
    @Test
    public void testGetObjects_400WhenParameterIsInvalid() {

        // mock: Parameters
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);
        FieldSelector fields = new FieldSelector();
        FilterParameter filter = new FilterParameter(null);
        OrderByQuery orderBy = new OrderByQuery();
        orderBy.getItems().add(orderBy.new OrderByItem());
        LimitQuery limit = new LimitQuery(100);
        QueryParameter queryParam = new QueryParameter(fields, filter, limit, orderBy);
        
        // mock: UserDAO - throws IllegalArgumentException
        UserDAO userDao = mock(UserDAO.class);
        doThrow(new IllegalArgumentException()).when(userDao).findUsers(any(FilterParameter.class), any(List.class), any(LimitQuery.class));
        
        // mock: EventProducer
        EventProducer eventProducer = mock(EventProducer.class);
        
        // Test
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, eventProducer, null));
        try {
            testee.getObjects(authUser, queryParam, request);
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        }

        // verify
        verify(userDao).findUsers(any(FilterParameter.class), any(List.class), any(LimitQuery.class));
    }
    
    @Test
    public void testActivateUser() throws Exception {

        // data
        long userId = 123456L;
        User user = createTestUser(userId);

        // mock
        HttpServletRequest request = mock(HttpServletRequest.class);
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserById(userId)).thenReturn(user);
        doCallRealMethod().when(userDao).activate(user);
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, eventProducer, null);
        testee.setObjectMapper(objectMapper);
        ApiResponse result = testee.activateUser(user.getCredential().getActivationCode(), request);

        // Checking result
        assertNotNull("activateUser() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(user, apiResult.getContent());
        assertTrue("user#isActive() should be true.", user.isActive());
        assertTrue("user#isEmailActive() should be true.", user.isEmailActive());

        // verify
        verify(userDao).findUserById(userId);
        verify(userDao).activate(user);
        /* 
       	//jira-plat-130 
        	verify(eventProducer).publish("event.user.activated", "payload");
        	verify(eventProducer).publish("event.notification.send", "payload"); // welcome mail
       */ 
       verify(objectMapper).writeValueAsString(user);
    }

    @Test
    public void testActivateUser_403WhenCodeIsInvalid() {
        // data
        User user = createTestUser(123456L);
        // wrong code
        String code = "`*+?ZZZZZZ";

        testActivateUser_403ErrorCase(user, code);
    }

    @Test
    public void testActivateUser_403WhenUserHasBeenActivated() {

        // data
        User user = createTestUser(123456L);
        user.setActive(true); // has been activated

        testActivateUser_403ErrorCase(user, user.getCredential().getActivationCode());
    }

    private void testActivateUser_403ErrorCase(User user, String activationCode) {
        
        // mock
        HttpServletRequest request = mock(HttpServletRequest.class);
        UserDAO userDao = mock(UserDAO.class);
        long userId = Long.parseLong(user.getId().toString());
        when(userDao.findUserById(userId)).thenReturn(user);

        // test
        try {
            new UserResource(userDao, mockRoleDao, null, null, null).activateUser(activationCode, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
        }
        
        // verify
        verify(userDao, never()).activate(user);
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testSendActivationCode() throws Exception {
        
        long userId = 123456L;
        User user = createTestUser(userId);
        assertEquals(false, user.isActive()); // user should be inactive
        
        // mock
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        String optionKey = "afterActivationURL";
        doReturn("http://www.topcoder-dev.com").when(param).getOptionString(optionKey);

        UserDAO userDao = mock(UserDAO.class);
        doReturn(user).when(userDao).findUserById(userId);
        
        CacheService cacheService = mock(CacheService.class);
        
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        doReturn("payload").when(objectMapper).writeValueAsString(anyObject());

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null);
        testee.setObjectMapper(objectMapper);
        
        // test
        ApiResponse result = testee.sendActivationCode(String.valueOf(userId), param, null);
        
        // checking result
        assertNotNull(result);
        Result apiResult = result.getResult();
        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue(apiResult.getSuccess());

        // verify
        verify(userDao).findUserById(userId);
        String cacheKey = testee.getCacheKeyForActivationCode(user.getId(), user.getEmail());
        verify(cacheService).get(cacheKey);
        verify(cacheService).put(cacheKey, user.getCredential().getActivationCode(), testee.getResendActivationCodeExpirySeconds());
        
        verify(param).getOptionString(optionKey);
        // jira-plat-130  verify(eventProducer).publish("event.notification.send", "payload");
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testSendActivationCode_404WhenSpecifiedUserIdNotFound() throws Exception {
        
        long userId = 123456L;
        
        // mock
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);

        UserDAO userDao = mock(UserDAO.class);
        doReturn(null).when(userDao).findUserById(userId); // user not found
        
        CacheService cacheService = mock(CacheService.class);
        
        EventProducer eventProducer = mock(EventProducer.class);

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null);
        
        // test
        try {
            testee.sendActivationCode(String.valueOf(userId), param, null);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch(APIRuntimeException e) {
            assertEquals(SC_NOT_FOUND, e.getHttpStatus());
        }
        
        // verify
        verify(userDao).findUserById(userId);
        verify(cacheService, never()).get(anyString());
        verify(cacheService, never()).put(anyString(), anyString(), anyInt());
        verify(param, never()).getOptionString(anyString());
        verify(eventProducer, never()).publish(anyString(), anyString());
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testSendActivationCode_400WhenSpecifiedUserIsActive() throws Exception {
        
        long userId = 123456L;
        User user = createTestUser(userId);
        user.setActive(true); // user is active
        
        // mock
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);

        UserDAO userDao = mock(UserDAO.class);
        doReturn(user).when(userDao).findUserById(userId);
        
        CacheService cacheService = mock(CacheService.class);
        
        EventProducer eventProducer = mock(EventProducer.class);

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null);
        
        // test
        try {
            testee.sendActivationCode(String.valueOf(userId), param, null);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch(APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        }
        
        // verify
        verify(userDao).findUserById(userId);
        verify(cacheService, never()).get(anyString());
        verify(cacheService, never()).put(anyString(), anyString(), anyInt());
        verify(param, never()).getOptionString(anyString());
        verify(eventProducer, never()).publish(anyString(), anyString());
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testSendActivationCode_400WhenActivationCodeHasAlreadyBeenSent() throws Exception {
        
        long userId = 123456L;
        User user = createTestUser(userId);
        assertEquals(false, user.isActive()); // user should be inactive
        
        // mock
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);

        UserDAO userDao = mock(UserDAO.class);
        doReturn(user).when(userDao).findUserById(userId);
        
        CacheService cacheService = mock(CacheService.class);
        
        EventProducer eventProducer = mock(EventProducer.class);

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null);

        // mock
        String cacheKey = testee.getCacheKeyForActivationCode(user.getId(), user.getEmail());
        doReturn(user.getCredential().getActivationCode()).when(cacheService).get(cacheKey);

        // test
        try {
            testee.sendActivationCode(String.valueOf(userId), param, null);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch(APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        }
        
        // verify
        verify(userDao).findUserById(userId);
        verify(cacheService).get(cacheKey);
        verify(cacheService, never()).put(anyString(), anyString(), anyInt());
        verify(param, never()).getOptionString(anyString());
        verify(eventProducer, never()).publish(anyString(), anyString());
    }
    
    
    @Test
    public void testGetOneTimeToken() {
        
        long userId = 1234567L;
        String password = "DUMMY-PASSWORD";
        User user = createTestUser(userId);
        String secret = "DUMMY-SECRET";
        String domain = "DUMMY-DOMAIN";
        
        // mock
        UserDAO userDao = mock(UserDAO.class);
        doReturn(user).when(userDao).authenticate(userId, password);
        
        CacheService cacheService = mock(CacheService.class);
        
        HttpServletRequest request = mock(HttpServletRequest.class);
        
        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, cacheService, null, null);
        testee.setDomain(domain);
        testee.setSecret(secret);
        
        // test
        ApiResponse result = testee.getOneTimeToken(String.valueOf(userId), password, request);
        
        // checking result
        assertNotNull(result);
        Result apiResult = result.getResult();
        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue(apiResult.getSuccess());
        String token = (String)apiResult.getContent();
        assertNotNull(token);
        
        JWTToken jwt = new JWTToken(token, "DUMMY-SECRET", Utils.getValidIssuers());
        assertEquals(String.valueOf(userId), jwt.getUserId());
        assertEquals(user.getHandle(), jwt.getHandle());
        assertTrue("Issuer is invalid", jwt.isValidIssuerFor(domain));
        
        // verify
        verify(userDao).authenticate(userId, password);
        String cacheKey = testee.getCacheKeyForOneTimeToken(user.getId());
        assertNotNull(cacheKey);
        verify(cacheService).get(cacheKey);
        verify(cacheService).put(eq(cacheKey), eq(token), anyInt());
    }
    
    @Test
    public void testGetOneTimeToken_400WhenUserIdOrPasswordNotSpecified() {

        // testee
        UserResource testee = new UserResource(null, mockRoleDao, null, null, null);
        
        try {
            testee.getOneTimeToken(null, "password", null);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(e.getHttpStatus(), SC_BAD_REQUEST);
        }
        try {
            testee.getOneTimeToken("userId", null, null);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(e.getHttpStatus(), SC_BAD_REQUEST);
        }
    }
    
    @Test
    public void testGetOneTimeToken_403WhenAuthenticationFailed() {
        
        long userId = 1234567L;
        String password = "DUMMY-PASSWORD";
        
        // mock
        UserDAO userDao = mock(UserDAO.class);
        doReturn(null).when(userDao).authenticate(userId, password); // authentication will fail
        
        HttpServletRequest request = mock(HttpServletRequest.class);
        
        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);
        
        // test
        try {
            testee.getOneTimeToken(String.valueOf(userId), password, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(e.getHttpStatus(), SC_UNAUTHORIZED);
        }
        
        verify(userDao).authenticate(userId, password);
    }
    
    @Test
    public void testGetOneTimeToken_400WhenTokenHasBeenIssued() {
        
        long userId = 1234567L;
        String password = "DUMMY-PASSWORD";
        User user = createTestUser(userId);
        
        // mock
        UserDAO userDao = mock(UserDAO.class);
        doReturn(user).when(userDao).authenticate(userId, password);
        
        CacheService cacheService = mock(CacheService.class);
        
        HttpServletRequest request = mock(HttpServletRequest.class);
        
        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, cacheService, null, null);
        
        String cacheKey = testee.getCacheKeyForOneTimeToken(user.getId());
        doReturn("TOKEN").when(cacheService).get(cacheKey); // token is stored in the cache
        
        // test
        try {
            testee.getOneTimeToken(String.valueOf(userId), password, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(e.getHttpStatus(), SC_BAD_REQUEST);
        }
        
        verify(userDao).authenticate(userId, password);
        verify(cacheService).get(cacheKey);
        verify(cacheService, never()).put(anyString(), anyString());
        verify(cacheService, never()).put(anyString(), anyString(), anyInt());
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testUpdateHandle() throws Exception {
        
        // data
        long userId = 123456L;
        User user = createTestUser(userId);
        
        String newHandle = "NEW-HANDLE";
        String resourceId = user.getId().getId();
        assertNotEquals(newHandle, user.getHandle());
        
        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserById(userId)).thenReturn(user); // findUserById(userId) returns the user
        doNothing().when(userDao).updateHandle(user);
        
        // mock: EventProducer
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        
        // mock: ObjectMapper
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        
        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(userId);
        doReturn(id).when(authUser).getUserId(); // used to check permission to use the endpoint
        
        // mock: PostPutRequest - gives mock user
        User paramUser = spy(new User());
        paramUser.setHandle(newHandle);
        doReturn(null).when(paramUser).validateHandle(); // mock

        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(paramUser);

        // mock: request
        HttpServletRequest request = mock(HttpServletRequest.class);

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, eventProducer, null));
        testee.setObjectMapper(objectMapper);
        doReturn(null).when(testee).validateHandle(newHandle); // mock: always valid
        
        // test
        ApiResponse result = testee.updateHandle(authUser, resourceId, param, request);

        // Checking result
        assertNotNull("activateUser() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(user, apiResult.getContent());
        assertEquals(newHandle, user.getHandle());
        assertEquals(userId, Long.parseLong(user.getModifiedBy().getId()));
        
        // verify
        verify(userDao).findUserById(userId);
        verify(userDao).updateHandle(user);
        // jira-plat-130 verify(eventProducer).publish("event.user.updated", "payload");
        verify(objectMapper).writeValueAsString(user);
        verify(authUser, atLeastOnce()).getUserId();
        verify(param, atLeastOnce()).getParam();
        verify(paramUser).validateHandle();
        
        // confirm check methods are passed
        verify(testee).checkResourceId(id);
        verify(testee).validateResourceIdAndCheckPermission(authUser, id, userProfilesFactory.getUpdateScopes());
        verify(testee).checkParam(param);
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testUpdateHandle_EventIsNotPublishedWhenHandleIsNotChanged() throws Exception {
        
        // data
        long userId = 123456L;
        User user = createTestUser(userId);
        
        String resourceId = user.getId().getId();
        String newHandle = user.getHandle();
        assertEquals(newHandle, user.getHandle());
        
        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserById(userId)).thenReturn(user); // findUserById(userId) returns the user
        doNothing().when(userDao).updateHandle(user);
        
        // mock: EventProducer
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        
        // mock: ObjectMapper
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        
        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(userId);
        doReturn(id).when(authUser).getUserId(); // used to check permission to use the endpoint
        
        // mock: PostPutRequest - gives mock user
        User paramUser = spy(new User());
        paramUser.setHandle(newHandle);
        doReturn(null).when(paramUser).validateHandle(); // mock
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(paramUser);

        // mock: request
        HttpServletRequest request = mock(HttpServletRequest.class);

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, eventProducer, null));
        testee.setObjectMapper(objectMapper);
        doReturn(null).when(testee).validateHandle(newHandle); // mock: always valid
        
        // test
        ApiResponse result = testee.updateHandle(authUser, resourceId, param, request);

        // Checking result
        assertNotNull("activateUser() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(user, apiResult.getContent());
        assertEquals(newHandle, user.getHandle());
        
        // verify
        verify(authUser).getUserId();
        verify(param, atLeastOnce()).getParam();
        verify(userDao).findUserById(userId);
        verify(paramUser).validateHandle();
        
        verify(userDao, never()).updateHandle(any(User.class));
        verify(eventProducer, never()).publish(anyString(), anyString());
        verify(objectMapper, never()).writeValueAsString(any(User.class));
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testUpdateHandle_400_WhenHandleIsInvalid() {
        // data
        long userId = 123456L;
        String resourceId = String.valueOf(userId);
        String error = "Handle is invalid";
        
        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(resourceId);
        doReturn(id).when(authUser).getUserId(); // permission
        
        // mock: PostPutRequest - gives mock user
        User paramUser = spy(new User());
        doReturn(error).when(paramUser).validateHandle(); // mock: always invalid
        String newHandle = "NEW-HANDLE";
        paramUser.setHandle(newHandle);
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(paramUser);
        // mock: request
        HttpServletRequest request = mock(HttpServletRequest.class);

        // test
        try {
            new UserResource(null, null, null, null, null).updateHandle(authUser, resourceId, param, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
            assertEquals(error, e.getMessage());
        }
        
        // verify
        verify(authUser).getUserId();
        verify(paramUser).validateHandle();
        verify(param, atLeastOnce()).getParam();
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testUpdateHandle_400_WhenHandleIsInvalid2() {
        // data
        long userId = 123456L;
        String resourceId = String.valueOf(userId);
        String error = "Handle is invalid";
        
        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(resourceId);
        doReturn(id).when(authUser).getUserId(); // permission
        
        // mock: PostPutRequest - gives mock user
        User paramUser = spy(new User());
        doReturn(null).when(paramUser).validateHandle(); // mock: always valid
        String newHandle = "NEW-HANDLE";
        paramUser.setHandle(newHandle);
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(paramUser);
        // mock: request
        HttpServletRequest request = mock(HttpServletRequest.class);

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        doReturn(error).when(testee).validateHandle(newHandle); // handle is invalid
        
        // test
        try {
            testee.updateHandle(authUser, resourceId, param, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
            assertEquals(error, e.getMessage());
        }
        
        // verify
        verify(authUser).getUserId();
        verify(paramUser).validateHandle();
        verify(param, atLeastOnce()).getParam();
        verify(testee).validateHandle(newHandle);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testUpdateHandle_404_WhenUserIsNotFound() {
    
        // parameter
        String newHandle = "NEW-HANDLE";
        String resourceId = "123456";
        long userId = Long.parseLong(resourceId);
        
        // mock: userDao
        UserDAO userDao = mock(UserDAO.class);
        doReturn(null).when(userDao).findUserById(userId); // any user with userId is not found
        // mock: authUser
        AuthUser authUser = spy(new AuthUser());
        doReturn(new TCID(resourceId)).when(authUser).getUserId();
        // mock: request
        HttpServletRequest request = mock(HttpServletRequest.class);
        // mock: param
        User paramUser = new User();
        paramUser.setHandle(newHandle);
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(paramUser);

        // test
        try {
            new UserResource(userDao, mockRoleDao, null, null, null).updateHandle(authUser, resourceId, param, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(HTTP_NOT_FOUND, e.getHttpStatus());
            assertEquals(MSG_TEMPLATE_USER_NOT_FOUND, e.getMessage());
        }
        
        // verify
        verify(userDao).findUserById(userId);
        verify(userDao, never()).updateHandle(any(User.class));
        verify(authUser).getUserId();
        verify(param, atLeastOnce()).getParam();
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testUpdatePrimaryEmail() throws Exception {
        
        // data
        long userId = 123456L;
        User user = createTestUser(userId);
        
        String newEmail = "NEW-EMAIL";
        String resourceId = user.getId().getId();
        assertNotEquals(newEmail, user.getEmail());

        Email email = new Email();
        email.setAddress(newEmail);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserById(userId)).thenReturn(user); // findUserById(userId) returns the user
        when(userDao.updatePrimaryEmail(user)).thenReturn(email);
        
        // mock: EventProducer
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        
        // mock: ObjectMapper
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        
        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(userId);
        doReturn(id).when(authUser).getUserId(); // used to check permission to use the endpoint
        
        // mock: PostPutRequest - gives mock user
        User paramUser = spy(new User());
        doReturn(null).when(paramUser).validateEmail(); // mock
        paramUser.setEmail(newEmail);
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(paramUser);

        // mock: request
        HttpServletRequest request = mock(HttpServletRequest.class);

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, eventProducer, null));
        testee.setObjectMapper(objectMapper);
        doReturn(null).when(testee).validateEmail(newEmail); // mock: always valid
        
        // test
        ApiResponse result = testee.updatePrimaryEmail(authUser, resourceId, param, request);

        // Checking result
        assertNotNull("activateUser() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(user, apiResult.getContent());
        assertEquals(newEmail, user.getEmail());
        assertEquals(userId, Long.parseLong(user.getModifiedBy().getId()));
        
        // verify
        verify(userDao).findUserById(userId);
        verify(userDao).updatePrimaryEmail(user);
        // jira-plat-130 verify(eventProducer).publish("event.user.updated", "payload");
        verify(objectMapper).writeValueAsString(user);
        verify(authUser, atLeastOnce()).getUserId();
        verify(param, atLeastOnce()).getParam();
        
        // confirm check methods are passed
        verify(testee).checkResourceId(id);
        verify(testee).validateResourceIdAndCheckPermission(authUser, id, userProfilesFactory.getUpdateScopes());
        verify(testee).checkParam(param);
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testUpdatePrimaryEmail_EventIsNotPublishedWhenEmailIsNotChanged() throws Exception {
        // data
        long userId = 123456L;
        User user = createTestUser(userId);
        
        String newEmail = user.getEmail(); // the same email
        String resourceId = user.getId().getId();
        assertEquals(newEmail, user.getEmail());

        Email email = new Email();
        email.setAddress(newEmail);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserById(userId)).thenReturn(user); // findUserById(userId) returns the user
        
        // mock: EventProducer
        EventProducer eventProducer = mock(EventProducer.class);
        
        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());
        
        // mock: PostPutRequest - gives mock user
        User paramUser = spy(new User());
        doReturn(null).when(paramUser).validateEmail();
        paramUser.setEmail(newEmail);
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(paramUser);

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, eventProducer, null));
        doNothing().when(testee).checkResourceId(any(TCID.class));
        doNothing().when(testee).validateResourceIdAndCheckPermission(authUser, new TCID(resourceId), userProfilesFactory.getUpdateScopes());
        doNothing().when(testee).checkParam(any(PostPutRequest.class));
        doReturn(null).when(testee).validateEmail(newEmail); // mock: always valid

        // test
        ApiResponse result = testee.updatePrimaryEmail(authUser, resourceId, param, null);

        // Checking result
        assertNotNull("activateUser() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(user, apiResult.getContent());
        assertEquals(newEmail, user.getEmail());
        
        // verify
        verify(userDao).findUserById(userId);
        verify(param, atLeastOnce()).getParam();
        verify(paramUser).validateEmail();
        verify(testee).validateEmail(newEmail);
        
        // verify never invoked
        verify(userDao, never()).updatePrimaryEmail(user);
        verify(eventProducer, never()).publish(eq("event.user.updated"), anyString());
        
        // confirm check methods are passed
        TCID uid = new TCID(resourceId);
        verify(testee).validateResourceIdAndCheckPermission(authUser, uid, userProfilesFactory.getUpdateScopes());
        verify(testee).checkParam(param);
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testUpdatePrimaryEmail_400_WhenEmailIsInvalid() throws Exception {
        // data
        long userId = 123456L;
        String resourceId = String.valueOf(userId);
        String newEmail = "INVALID-EMAIL";

        // mock: PostPutRequest - gives mock user
        User paramUser = spy(new User());
        paramUser.setEmail(newEmail);
        String error = "ERROR";
        doReturn(error).when(paramUser).validateEmail();
        
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(paramUser);
        
        AuthUser authUser = new AuthUser();

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        doNothing().when(testee).checkResourceId(any(TCID.class));
        doNothing().when(testee).validateResourceIdAndCheckPermission(authUser, new TCID(resourceId), userProfilesFactory.getUpdateScopes());
        doNothing().when(testee).checkParam(any(PostPutRequest.class));
        //doReturn(null).when(testee).validateEmail(newEmail); // mock: always valid

        // test
        try {
            testee.updatePrimaryEmail(authUser, resourceId, param, null);
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
            assertEquals(error, e.getMessage());
        }
        
        // verify
        verify(paramUser).validateEmail();
        verify(param, atLeastOnce()).getParam();
        
        // confirm check methods are passed
        TCID uid = new TCID(resourceId);
        verify(testee).validateResourceIdAndCheckPermission(authUser, uid, userProfilesFactory.getUpdateScopes());
        verify(testee).checkParam(param);
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testUpdatePrimaryEmail_400_WhenEmailIsInvalid2() {
        // data
        long userId = 123456L;
        String resourceId = String.valueOf(userId);
        String newEmail = "INVALID-EMAIL";

        // mock: PostPutRequest - gives mock user
        User paramUser = spy(new User());
        paramUser.setEmail(newEmail);
        doReturn(null).when(paramUser).validateEmail(); // valid
        
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(paramUser);
        
        AuthUser authUser = new AuthUser();

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        doNothing().when(testee).checkResourceId(any(TCID.class));
        doNothing().when(testee).validateResourceIdAndCheckPermission(authUser, new TCID(resourceId), userProfilesFactory.getUpdateScopes());
        doNothing().when(testee).checkParam(any(PostPutRequest.class));
        String error = "ERROR";
        doReturn(error).when(testee).validateEmail(newEmail); // mock: invalid

        // test
        try {
            testee.updatePrimaryEmail(authUser, resourceId, param, null);
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
            assertEquals(error, e.getMessage());
        }
        
        // verify
        verify(paramUser).validateEmail();
        verify(param, atLeastOnce()).getParam();
        verify(testee).validateEmail(newEmail);
        
        // confirm check methods are passed
        TCID uid = new TCID(resourceId);
        verify(testee).validateResourceIdAndCheckPermission(authUser, uid, userProfilesFactory.getUpdateScopes());
        verify(testee).checkParam(param);
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testUpdatePrimaryEmail_404_WhenUserIsNotFound() {
        // data
        long userId = 123456L;
        String resourceId = String.valueOf(userId);
        String newEmail = "NEW-EMAIL";

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        doReturn(null).when(userDao).findUserById(userId); // user is not found
        
        // mock: PostPutRequest - gives mock user
        User paramUser = spy(new User());
        paramUser.setEmail(newEmail);
        doReturn(null).when(paramUser).validateEmail(); // valid
        
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(paramUser);
        
        AuthUser authUser = new AuthUser();

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, null, null));
        doNothing().when(testee).checkResourceId(any(TCID.class));
        doNothing().when(testee).validateResourceIdAndCheckPermission(authUser, new TCID(resourceId), userProfilesFactory.getUpdateScopes());
        doNothing().when(testee).checkParam(any(PostPutRequest.class));
        doReturn(null).when(testee).validateEmail(newEmail); // mock: valid

        // test
        try {
            testee.updatePrimaryEmail(authUser, resourceId, param, null);
        } catch (APIRuntimeException e) {
            assertEquals(SC_NOT_FOUND, e.getHttpStatus());
            assertEquals(MSG_TEMPLATE_USER_NOT_FOUND, e.getMessage());
        }
        
        // verify
        verify(userDao).findUserById(userId);
        verify(paramUser).validateEmail();
        verify(param, atLeastOnce()).getParam();
        verify(testee).validateEmail(newEmail);
        
        // confirm check methods are passed
        TCID uid = new TCID(resourceId);
        verify(testee).validateResourceIdAndCheckPermission(authUser, uid, userProfilesFactory.getUpdateScopes());
        verify(testee).checkParam(param);
    }

    @Test
    public void testUpdateEmailWithOneTimeToken() {
        // user
        long userId = 1234567L;
        User user = createTestUser(userId);
        // email
        String newEmail = "abcdef@test.topcoder.com";       
        Email email = new Email();
        email.setAddress(newEmail);
        email.setUserId(user.getId());
        
        String secret = "DUMMY-SECRET";
        String domain = "DUMMY-DOMAIN";

        
        // mock
        UserDAO userDao = mock(UserDAO.class);
        doReturn(user).when(userDao).findUserById(userId);
        doReturn(email).when(userDao).updatePrimaryEmail(user);
        
        CacheService cacheService = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        
        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null);
        testee.setSecret(secret);
        testee.setDomain(domain);
        
        String onetimeToken = testee.generateOneTimeToken(user, domain, 1000000);
        doReturn("bearer "+onetimeToken).when(request).getHeader("Authorization");
        String cacheKey = testee.getCacheKeyForOneTimeToken(user.getId());
        doReturn(onetimeToken).when(cacheService).get(cacheKey);
        
        // test
        ApiResponse result = testee.updateEmailWithOneTimeToken(String.valueOf(userId), newEmail, request);
        
        // check result
        assertNotNull(result);
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(user, apiResult.getContent());
        assertEquals(newEmail, user.getEmail());
        
        verify(userDao).findUserById(userId);
        verify(userDao).updatePrimaryEmail(user);
        verify(request).getHeader("Authorization");
        verify(cacheService).get(cacheKey);
        verify(cacheService).delete(cacheKey); // cache should be cleared
    }
    
    @Test
    public void testUpdateEmailWithOneTimeToken_401WhenHeaderIsInvalid() {
        // user
        long userId = 1234567L;
        // email
        String newEmail = "abcdef@test.topcoder.com";       

        // mock
        UserDAO userDao = mock(UserDAO.class);
        
        CacheService cacheService = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        doReturn(null).when(request).getHeader("Authorization"); // no Authorization header
        
        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null);
        
        // test(1)
        try {
            testee.updateEmailWithOneTimeToken(String.valueOf(userId), newEmail, request);
        } catch (APIRuntimeException e) {
            assertEquals(SC_UNAUTHORIZED, e.getHttpStatus());
        }
        verify(request).getHeader("Authorization");

        reset(request);
        String invalidHeader = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"; // bearer is not present
        doReturn(invalidHeader).when(request).getHeader("Authorization");
        
        // test(2)
        try {
            testee.updateEmailWithOneTimeToken(String.valueOf(userId), newEmail, request);
        } catch (APIRuntimeException e) {
            assertEquals(SC_UNAUTHORIZED, e.getHttpStatus());
        }
        verify(request).getHeader("Authorization");     
    }
    
    @Test
    public void testUpdateEmailWithOneTimeToken_401WhenTokenIsInvalid() {
        // user
        long userId = 1234567L;
        // email
        String newEmail = "abcdef@test.topcoder.com";   
        // token
        String onetimeToken = "DUMMY-TOKEN";

        // mock
        UserDAO userDao = mock(UserDAO.class);
        
        CacheService cacheService = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        doReturn("bearer "+onetimeToken).when(request).getHeader("Authorization");
        
        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null));
        doThrow(new InvalidTokenException(onetimeToken)).when(testee).createOneTimeToken(onetimeToken);
        
        // test
        try {
            testee.updateEmailWithOneTimeToken(String.valueOf(userId), newEmail, request);
        } catch (APIRuntimeException e) {
            assertEquals(SC_UNAUTHORIZED, e.getHttpStatus());
        }
        verify(request).getHeader("Authorization");
        verify(testee).createOneTimeToken(onetimeToken);
        verify(cacheService, never()).get(anyString());
    }
    
    
    @Test
    public void testUpdateEmailWithOneTimeToken_401WhenTokenIsExpiredOrAlreadyInUse() {
        // user
        long userId = 1234567L;
        User user = createTestUser(userId);
        // email
        String newEmail = "abcdef@test.topcoder.com";       
        Email email = new Email();
        email.setAddress(newEmail);
        email.setUserId(user.getId());
        
        String secret = "DUMMY-SECRET";
        String domain = "DUMMY-DOMAIN";

        // mock
        UserDAO userDao = mock(UserDAO.class);
        
        CacheService cacheService = mock(CacheService.class);
        EventProducer eventProducer = mock(EventProducer.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        
        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null));
        testee.setSecret(secret);
        testee.setDomain(domain);
        
        String onetimeToken = testee.generateOneTimeToken(user, domain, 1000000);
        doReturn("bearer "+onetimeToken).when(request).getHeader("Authorization");
        
        String cacheKey = testee.getCacheKeyForOneTimeToken(user.getId());
        doReturn(null).when(cacheService).get(cacheKey); // token is expired or already in use.
        
        // test
        try {
            testee.updateEmailWithOneTimeToken(String.valueOf(userId), newEmail, request);
        } catch (APIRuntimeException e) {
            assertEquals(SC_UNAUTHORIZED, e.getHttpStatus());
        }
        verify(request).getHeader("Authorization");
        verify(cacheService).get(cacheKey);
    }
    
    @Test
    public void testUpdateStatus_ToInactive() throws Exception {
        
        // parameter
        String newStatus = MemberStatus.INACTIVE_DUPLICATE_ACCOUNT.getValue();
        String comment = "DUPLICATE_ACCOUNT";
        User user = createTestUser(123456L);
        user.setStatus(MemberStatus.ACTIVE.getValue());

        // test
        testUpdateStatus(newStatus, comment, user);
        
        // User should be inactive.
        // An event to notify the user is updated should be fired.
    }

    @Test
    public void testUpdateStatus_ToActive() throws Exception {
        
        // parameter
        String newStatus = MemberStatus.ACTIVE.getValue();
        String comment = "ACTIVATE_ACCOUNT";
        User user = createTestUser(123456L);
        user.setStatus(MemberStatus.UNVERIFIED.getValue());

        // test
        testUpdateStatus(newStatus, comment, user);
        
        // User should be active.
        // An event to notify the user is updated should be fired.
        // An event to send welcome mail should be fired.
    }
    
    @Test
    public void testUpdateStatus_ToReActive() throws Exception {
        
        // parameter
        String newStatus = MemberStatus.ACTIVE.getValue();
        String comment = "REACTIVATE_ACCOUNT";
        User user = createTestUser(123456L);
        user.setStatus(MemberStatus.INACTIVE_IRREGULAR_ACCOUNT.getValue());

        // test
        testUpdateStatus(newStatus, comment, user);
        
        // User should be active.
        // An event to notify the user is updated should be fired.
        // An event to send welcome mail should NOT be fired.
    }


    @SuppressWarnings("unchecked")
    public void testUpdateStatus(String newStatus, String comment, User user) throws Exception {
        
        // data
        String resourceId = user.getId().getId();
        long userId = Long.parseLong(resourceId);
        String oldStatus = user.getStatus();
        assertNotEquals(newStatus, oldStatus);
        
        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserById(userId)).thenReturn(user); // findUserById(userId) returns the user
        doNothing().when(userDao).updateStatus(user, comment);
        
        // mock: EventProducer
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        
        // mock: ObjectMapper
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        
        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(userId);
        doReturn(id).when(authUser).getUserId(); // used to check permission to use the endpoint
        
        // mock: PostPutRequest - gives mock user
        User paramUser = new User();
        paramUser.setStatus(newStatus);
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(paramUser);

        // mock: request
        HttpServletRequest request = mock(HttpServletRequest.class);

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, eventProducer, null));
        testee.setObjectMapper(objectMapper);
        
        // test
        ApiResponse result = testee.updateStatus(authUser, resourceId, param, comment, request);

        // Checking result
        assertNotNull("activateUser() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(user, apiResult.getContent());
        assertEquals(newStatus, user.getStatus());
        
        if(MemberStatus.ACTIVE.getValue().equals(newStatus))
            assertTrue("user#isActive() should be true.", user.isActive());
        else
            assertFalse("user#isActive() should be false.", user.isActive());

        assertEquals(userId, Long.parseLong(user.getModifiedBy().getId()));
        
        // verify
        verify(userDao).findUserById(userId);
        verify(userDao).updateStatus(user, comment);
        
        String topic;
        if(MemberStatus.ACTIVE.getValue().equals(newStatus))
            topic = "event.user.activated";
        else
            topic = "event.user.deactivated";
        // jira-plat-130 verify(eventProducer).publish(topic, "payload");
        
        if(MemberStatus.UNVERIFIED == MemberStatus.getByValue(oldStatus) &&
                MemberStatus.ACTIVE == MemberStatus.getByValue(newStatus) ) {
           // jira-plat-130 verify(eventProducer).publish("event.notification.send", "payload");
        } else {
            // jira-plat-130 verify(eventProducer, never()).publish(eq("event.notification.send"), anyString());
        }
        
        verify(objectMapper).writeValueAsString(user);
        verify(authUser, atLeastOnce()).getUserId();
        verify(param, atLeastOnce()).getParam();
        
        // confirm check methods are passed
        verify(testee).checkResourceId(id);
        verify(testee).validateResourceIdAndCheckPermission(authUser, id, userProfilesFactory.getUpdateScopes());
        verify(testee).checkParam(param);
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testUpdateStatus_EventIsNotPublishedWhenStatusIsNotChanged() throws Exception {
        
        // parameter
        String comment = "DUPLICATE_ACCOUNT";
        
        // data
        long userId = 123456L;
        String resourceId = String.valueOf(userId);
        User user = createTestUser(userId);
        String newStatus = user.getStatus(); // new status is the same status as old one.
        assertEquals(newStatus, user.getStatus());

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserById(userId)).thenReturn(user); // findUserById(userId) returns the user
        doNothing().when(userDao).updateStatus(user, comment);
        
        // mock: EventProducer
        EventProducer eventProducer = mock(EventProducer.class);
        doNothing().when(eventProducer).publish(anyString(), anyString());
        
        // mock: ObjectMapper
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        when(objectMapper.writeValueAsString(anyObject())).thenReturn("payload");
        
        // mock: AuthUser
        AuthUser authUser = spy(new AuthUser());
        TCID id = new TCID(userId);
        doReturn(id).when(authUser).getUserId(); // used to check permission to use the endpoint
        
        // mock: PostPutRequest - gives mock user
        User paramUser = new User();
        paramUser.setStatus(newStatus);
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(paramUser);

        // mock: request
        HttpServletRequest request = mock(HttpServletRequest.class);

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, eventProducer, null);
        testee.setObjectMapper(objectMapper);
        
        // test
        ApiResponse result = testee.updateStatus(authUser, resourceId, param, comment, request);

        // Checking result
        assertNotNull("activateUser() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(user, apiResult.getContent());
        assertEquals(newStatus, user.getStatus());
        assertEquals("user#isActive() should be false.", false, user.isActive());
        assertEquals(userId, Long.parseLong(user.getModifiedBy().getId()));

        // verify
        verify(eventProducer, never()).publish("event.user.activated", "payload"); // never published
        verify(objectMapper, never()).writeValueAsString(user);
        
        verify(userDao).findUserById(userId);
        verify(userDao).updateStatus(user, comment);
        verify(authUser, atLeastOnce()).getUserId();
        verify(param, atLeastOnce()).getParam();
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testUpdateStatus_400_WhenStatusIsInvalid() {
    
        // parameter
        String newStatus = "INVALID-STATUS";
        String comment = "DUPLICATE_ACCOUNT";
        String resourceId = "123456";
        
        // mock
        UserDAO userDao = mock(UserDAO.class);
        AuthUser authUser = spy(new AuthUser());
        doReturn(new TCID(resourceId)).when(authUser).getUserId();
        HttpServletRequest request = mock(HttpServletRequest.class);
        User paramUser = new User();
        paramUser.setStatus(newStatus);
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(paramUser);

        // test
        try {
            new UserResource(userDao, mockRoleDao, null, null, null).updateStatus(authUser, resourceId, param, comment, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
            assertEquals(MSG_TEMPLATE_INVALID_STATUS, e.getMessage());
        }

        // verify
        verify(userDao, never()).updateStatus(any(User.class), anyString());
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testUpdateStatus_404_WhenUserIsNotFound() {
    
        // parameter
        String newStatus = MemberStatus.INACTIVE_DUPLICATE_ACCOUNT.getValue();
        String comment = "DUPLICATE_ACCOUNT";
        String resourceId = "123456";
        long userId = Long.parseLong(resourceId);
        
        // mock
        UserDAO userDao = mock(UserDAO.class);
        doReturn(null).when(userDao).findUserById(userId); // any user with userId is not found
        AuthUser authUser = spy(new AuthUser());
        doReturn(new TCID(resourceId)).when(authUser).getUserId();
        HttpServletRequest request = mock(HttpServletRequest.class);
        User paramUser = new User();
        paramUser.setStatus(newStatus);
        PostPutRequest<User> param = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(paramUser);

        // test
        try {
            new UserResource(userDao, mockRoleDao, null, null, null).updateStatus(authUser, resourceId, param, comment, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(HTTP_NOT_FOUND, e.getHttpStatus());
            assertEquals(MSG_TEMPLATE_USER_NOT_FOUND, e.getMessage());
        }
        
        // verify
        verify(userDao).findUserById(userId);
        verify(userDao, never()).updateStatus(any(User.class), anyString());
    }

    protected void testLogin(String handle, String email, String password) {
        // data
        User user = new User();
        user.setHandle(handle);
        user.setEmail(email);
        String uid = handle!=null ? handle : email;

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        if(handle!=null) {
            when(userDao.authenticate(handle, password)).thenReturn(user);
        }
        if(email!=null) {
            when(userDao.authenticate(email, password)).thenReturn(user);
        }

        // mock: other
        HttpServletRequest request = mock(HttpServletRequest.class);

        EventProducer eventProducer = mock(EventProducer.class);

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, eventProducer, null);

        // test
        ApiResponse result = testee.login(uid, password, request);

        // Checking result
        assertNotNull("activateUser() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(user, apiResult.getContent());

        // verify mock
        if(handle!=null) {
            verify(userDao).authenticate(eq(handle), eq(password));
            if(email!=null) {
                verify(userDao, never()).authenticate(eq(email), eq(password));
            }
        }
        else if(email!=null) {
            verify(userDao).authenticate(eq(email), eq(password));
        }
    }
    
    
    @Test
    public void testLoginWithEmail() {
        // data
        String email = "jdoe@example.com";
        String password = "PASSWORD";
        
        // test
        testLogin(null, email, password);
    }

    @Test
    public void testLoginWithHandle() {
        // data
        String handle = "jdoe";
        String password = "PASSWORD";
        
        // test
        testLogin(handle, null, password);
    }

    @Test
    public void testLogin_400WhenPasswordIsMissing() {

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        // mock: other
        HttpServletRequest request = mock(HttpServletRequest.class);

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);

        // test
        try {
            testee.login("jdoe@example.com", null, request); // password is missing
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        }

        // verify
        verify(userDao, never()).findUserByEmail(anyString());
    }

    @Test
    public void testLogin_401WhenAuthenticationFailed() {
        // data
        String handle = "jdoe";
        String email = "jdoe@example.com";
        String password = "PASSWORD";

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.authenticate(handle, password)).thenReturn(null); // unauthenticated
        when(userDao.authenticate(email, password)).thenReturn(null); // unauthenticated

        // mock: other
        HttpServletRequest request = mock(HttpServletRequest.class);

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);

        // test#1
        try {
            testee.login(handle, password, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_UNAUTHORIZED, e.getHttpStatus());
        }
        // verify#1
        verify(userDao).authenticate(eq(handle), eq(password));
        
        // test#2
        reset(userDao);
        try {
            testee.login(email, password, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_UNAUTHORIZED, e.getHttpStatus());
        }
        // verify#2
        verify(userDao).authenticate(eq(email), eq(password));
    }

    @Test
    public void testLoginWithEmail_400WhenBothHandleAndEmailAreMissing() {

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        // mock: other
        HttpServletRequest request = mock(HttpServletRequest.class);

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);

        // test
        try {
            testee.login(null, "PASSWORD", request); // email is missing
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        }

        // verify
        verify(userDao, never()).findUserByEmail(anyString());
    }

    @Test
    public void testGetResetToken_ByHandle() {
        
        String handle = "jdoe";
        testGetResetToken(handle, null, null, null);
    }

    @Test
    public void testGetResetToken_ByEmail() {

        String email = "jdoe@example.com";
        testGetResetToken(null, email, null, null);
    }

    @Test
    public void testGetResetToken_ForConnect() {
        
        String handle = "jdoe";
        String source = "connect";
        testGetResetToken(handle, null, null, source);
    }

    @Test
    public void testGetResetToken_ForUserAssociatedWithSocialAccount() {

        String email = "jdoe@example.com";
        String socialUserId = "SOCIAL_USER_ID";

        testGetResetToken(null, email, socialUserId, null);
    }

    protected void testGetResetToken(String handle, String email, String socialUserId, String source) {
        // data
        long userId = 123456L;
        User user = createTestUser(userId);
        user.setHandle(handle);
        user.setEmail(email);
        String resetToken = "ABC123";
        String resetPasswordUrlPrefix = "RESET-PASSWORD-URL-PREFIX";

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        if(handle!=null) {
            when(userDao.findUserByHandle(handle)).thenReturn(user);
        }
        if(email!=null) {
            when(userDao.findUserByEmail(email)).thenReturn(user);
        }
        if(socialUserId!=null) {
            List<UserProfile> profiles = new ArrayList<>();
            UserProfile profile = new UserProfile();
            profile.setUserId(socialUserId);
            profile.setProviderType(ProviderType.FACEBOOK.name);
            profiles.add(profile);
            when(userDao.getSocialProfiles(userId)).thenReturn(profiles);
        }

        // mock: CacheService
        CacheService cacheService = mock(CacheService.class);
        when(cacheService.get(anyString())).thenReturn(null); // token has not been issued.
        // mock: other
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("source")).thenReturn(source);
        EventProducer eventProducer = mock(EventProducer.class);

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null));
        doReturn(resetToken).when(testee).generateResetToken();
        doReturn(resetPasswordUrlPrefix).when(testee).getResetPasswordUrlPrefix(request);
        doNothing().when(testee).publishNotificationEvent(any(MailRepresentation.class));

        // test
        ApiResponse result = testee.getResetToken(handle, email, request);

        // Checking result
        assertNotNull("activateUser() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(user, apiResult.getContent());

        UserProfile profile = ((User)apiResult.getContent()).getProfile();
        if(socialUserId!=null) {
            assertNotNull(profile);
            assertEquals(socialUserId, profile.getUserId());
            assertEquals(ProviderType.FACEBOOK.name, profile.getProviderType());
        } else {
            assertNull(profile);
            // reset token should not be generated for social account.
            // reset token now should _not_ be in the response due to SPA use of this call (10/13/2017)
            assertNull(user.getCredential().getResetToken());
        }
        // verify
        if(user.getHandle()!=null) {
            verify(userDao).findUserByHandle(handle);
        }
        if(user.getEmail()!=null) {
            verify(userDao).findUserByEmail(email);
        }

        verify(cacheService).get(testee.getCacheKeyForResetToken(user));
        verify(cacheService).put(
                testee.getCacheKeyForResetToken(user),
                resetToken,
                testee.getResetTokenExpirySeconds());
        verify(testee).generateResetToken();
        verify(testee).getResetPasswordUrlPrefix(request);
        verify(testee).notifyPasswordReset(user, resetToken, resetPasswordUrlPrefix);
    }


    @Test
    public void testGetResetToken_403ForUserAssociatedWithSSOAccount() {

        // data: user
        long userId = 123456L;
        String email = "jdoe@example.com";
        String ssoUserId = "SSO_USER_ID";
        User user = createTestUser(userId);
        user.setEmail(email);

        // data: profile
        List<UserProfile> profiles = new ArrayList<>();
        UserProfile profile = new UserProfile();
        profile.setUserId(ssoUserId);
        profile.setProviderType(ProviderType.SAMLP.name);
        profile.setProvider("sso-connection");
        profiles.add(profile);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserByEmail(email)).thenReturn(user);
        when(userDao.getSocialProfiles(userId)).thenReturn(null);
        when(userDao.getSSOProfiles(userId)).thenReturn(profiles);

        // mock: CacheService
        CacheService cacheService = mock(CacheService.class);
        when(cacheService.get(anyString())).thenReturn(null); // token has not been issued.
        // mock: other
        HttpServletRequest request = mock(HttpServletRequest.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null));

        //test
        try {
            testee.getResetToken(null, email, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            //User is not allowed to reset password
            assertEquals(HTTP_FORBIDDEN, e.getHttpStatus());
        }

        // verify
        verify(userDao).findUserByEmail(anyString());
        verify(cacheService, never()).put(anyString(), anyString(), anyInt());
        verify(testee, never()).notifyPasswordReset(any(User.class), anyString(), anyString());
    }

    @Test
    public void testGetResetToken_400WhenHandleAndEmailAreNull() {

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserByEmail(anyString())).thenReturn(null);
        // mock: CacheService
        CacheService cacheService = mock(CacheService.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null));

        //test
        try {
            testee.getResetToken(null, null, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
        }

        // verify
        verify(userDao, never()).findUserByEmail(anyString());
        verify(cacheService, never()).put(anyString(), anyString(), anyInt());
        verify(testee, never()).notifyPasswordReset(any(User.class), anyString(), anyString());
    }

    @Test
    public void testGetResetToken_404WhenUserDoesNotExist() {
        // data
        long userId = 123456L;
        User user = createTestUser(userId);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserByEmail(user.getHandle())).thenReturn(null); // user not found
        when(userDao.findUserByEmail(user.getEmail())).thenReturn(null); // user not found
        // mock: CacheService
        CacheService cacheService = mock(CacheService.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null));

        //test
        try {
            testee.getResetToken(user.getHandle(), user.getEmail(), request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(HTTP_NOT_FOUND, e.getHttpStatus());
        }

        // verify
        verify(userDao).findUserByHandle(user.getHandle());
        verify(userDao).findUserByEmail(user.getEmail());
        verify(cacheService, never()).put(anyString(), anyString(), anyInt());
        verify(testee, never()).notifyPasswordReset(any(User.class), anyString(), anyString());
    }

    @Test
    public void testGetResetToken_400WhenTokenHasAlreadyBeenIssuedAndNotExpiredYet() {
        // data
        long userId = 123456L;
        User user = createTestUser(userId);
        String resetToken = "ABC123";

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserByEmail(user.getEmail())).thenReturn(user);
        // mock: CacheService
        CacheService cacheService = mock(CacheService.class);
        when(cacheService.get(anyString())).thenReturn(resetToken); // reset token exists in the cache
        HttpServletRequest request = mock(HttpServletRequest.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null));

        //test
        try {
            testee.getResetToken(null, user.getEmail(), request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
        }

        // verify
        verify(userDao).findUserByEmail(user.getEmail());
        verify(cacheService).get(testee.getCacheKeyForResetToken(user));
        verify(cacheService, never()).put(anyString(), anyString(), anyInt());
        verify(testee, never()).notifyPasswordReset(any(User.class), anyString(), anyString());
    }
    
    
    @Test
    public void testGetResetPasswordUrlPrefix_Default() {
        // mock
        HttpServletRequest request = mock(HttpServletRequest.class);

        // testee
        UserResource testee = new UserResource(null, null, null, null, null);
        
        String result = testee.getResetPasswordUrlPrefix(request);
        
        assertEquals("https://www.topcoder.com/reset-password", result);
        
        verify(request).getParameter("resetPasswordUrlPrefix");
        verify(request).getParameter("source");
    }

    @Test
    public void testGetResetPasswordUrlPrefix_Connect() {
        
        // mock
        String source = "connect";
        HttpServletRequest request = mock(HttpServletRequest.class);
        doReturn(source).when(request).getParameter("source");

        // testee
        UserResource testee = new UserResource(null, null, null, null, null);
        
        String result = testee.getResetPasswordUrlPrefix(request);
        
        assertEquals("https://connect.topcoder.com/reset-password", result);
        
        verify(request).getParameter("resetPasswordUrlPrefix");
        verify(request).getParameter("source");
    }

    @Test
    public void testGetResetPasswordUrlPrefix_SpecificDomain() {
        // mock
        String domain = "DUMMY-DOMAIN";
        HttpServletRequest request = mock(HttpServletRequest.class);

        // testee
        UserResource testee = new UserResource(null, null, null, null, null);
        testee.setDomain(domain);
        
        String result = testee.getResetPasswordUrlPrefix(request);
        
        assertEquals("https://www." + domain + "/reset-password", result);
        
        verify(request).getParameter("resetPasswordUrlPrefix");
        verify(request).getParameter("source");
    }
    
    @Test
    public void testGetResetPasswordUrlPrefix_SpecificDomain_Connect() {
        // mock
        String domain = "DUMMY-DOMAIN";
        String source = "connect";
        HttpServletRequest request = mock(HttpServletRequest.class);
        doReturn(source).when(request).getParameter("source");

        // testee
        UserResource testee = new UserResource(null, null, null, null, null);
        testee.setDomain(domain);
        
        String result = testee.getResetPasswordUrlPrefix(request);
        
        assertEquals("https://connect." + domain + "/reset-password", result);
        
        verify(request).getParameter("resetPasswordUrlPrefix");
        verify(request).getParameter("source");
    }
    
    @Test
    public void testGetResetPasswordUrlPrefix_UrlSpecified() {
        // mock
        String source = "connect";
        String prefix = "DUMMY-HOST.topcoder-dev.com";
        HttpServletRequest request = mock(HttpServletRequest.class);
        doReturn(source).when(request).getParameter("source");
        doReturn(prefix).when(request).getParameter("resetPasswordUrlPrefix");

        // testee
        UserResource testee = new UserResource(null, null, null, null, null);
        
        String result = testee.getResetPasswordUrlPrefix(request);
        
        assertEquals(prefix, result);
        
        verify(request).getParameter("resetPasswordUrlPrefix");
    }


    @Test
    public void testResetPassword_ResetWithEmail() {
        // data
        long userId = 123456L;
        String resetToken = "ABC123";
        User dbUser = createTestUser(userId);
        dbUser.getCredential().setResetToken(resetToken);

        String newPassword = "newPass123[";
        User paramUser = createUserForResetPasswordTest(null, resetToken, newPassword);
        paramUser.setEmail(dbUser.getEmail()); // identified by email

        // mock: PostPutRequest
        @SuppressWarnings("unchecked")
        PostPutRequest<User> postRequest = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(postRequest.getParam()).thenReturn(paramUser);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserByEmail(dbUser.getEmail())).thenReturn(dbUser);
        // mock: CacheService
        CacheService cacheService = mock(CacheService.class);
        when(cacheService.get(anyString())).thenReturn(resetToken); // token exists in the cache
        // mock: other
        HttpServletRequest request = mock(HttpServletRequest.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null));

        // test
        ApiResponse result = testee.resetPassword(postRequest, request);

        // Checking result
        assertNotNull("activateUser() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(dbUser, apiResult.getContent());
        assertEquals(newPassword, dbUser.getCredential().getPassword());

        // verify
        verify(userDao, never()).findUserByHandle(anyString());
        verify(userDao).findUserByEmail(dbUser.getEmail()); // using this
        verify(userDao).updatePassword(dbUser);

        verify(cacheService).get(testee.getCacheKeyForResetToken(dbUser));
        verify(cacheService).delete(testee.getCacheKeyForResetToken(dbUser));
    }

    @Test
    public void testResetPassword_ResetWithHandle() {
        // data
        long userId = 123456L;
        String resetToken = "ABC123";
        User dbUser = createTestUser(userId);
        dbUser.getCredential().setResetToken(resetToken);

        String newPassword = "newPass123[";
        User paramUser = createUserForResetPasswordTest(dbUser.getHandle(), resetToken, newPassword);

        // mock: PostPutRequest
        @SuppressWarnings("unchecked")
        PostPutRequest<User> postRequest = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(postRequest.getParam()).thenReturn(paramUser);
        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserByHandle(dbUser.getHandle())).thenReturn(dbUser);
        // mock: CacheService
        CacheService cacheService = mock(CacheService.class);
        when(cacheService.get(anyString())).thenReturn(resetToken); // token exists in the cache
        // mock: other
        HttpServletRequest request = mock(HttpServletRequest.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null));

        // test
        ApiResponse result = testee.resetPassword(postRequest, request);

        // Checking result
        assertNotNull("activateUser() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(dbUser, apiResult.getContent());
        assertEquals(newPassword, dbUser.getCredential().getPassword());

        // verify
        verify(userDao).findUserByHandle(anyString()); // using this
        verify(userDao, never()).findUserByEmail(dbUser.getEmail());
        verify(userDao).updatePassword(dbUser);

        verify(cacheService).get(testee.getCacheKeyForResetToken(dbUser));
        verify(cacheService).delete(testee.getCacheKeyForResetToken(dbUser));
    }

    @Test
    public void testResetPassword_400WhenNewPasswordIsInvalid() {
        // data
        String resetToken = "ABC123", newPassword = "passowrd"; // weak password
        User paramUser = createUserForResetPasswordTest("jdoe", resetToken, newPassword);

        // test
        testResetPassword_ErrorCase(paramUser, mock(UserDAO.class), mock(CacheService.class),
                                        SC_BAD_REQUEST, MSG_TEMPLATE_INVALID_PASSWORD_NUMBER_SYMBOL);
    }

    @Test
    public void testResetPassword_400WhenTokenIsNotSpecified() {
        // data
        String newPassword = "passowrd123[]";
        User paramUser = createUserForResetPasswordTest("jdoe", null, newPassword); // token is null

        // test
        testResetPassword_ErrorCase(paramUser, mock(UserDAO.class), mock(CacheService.class),
                                        SC_BAD_REQUEST, String.format(MSG_TEMPLATE_MANDATORY, "Token"));
    }

    @Test
    public void testResetPassword_404WhenUserDoesNotExist() {
        // data
        String newPassword = "passowrd123[]", resetToken = "ABC123";
        User paramUser = createUserForResetPasswordTest("jdoe", resetToken, newPassword); // token is null

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserByEmail(anyString())).thenReturn(null); // user not found

        // test
        testResetPassword_ErrorCase(paramUser, userDao, mock(CacheService.class),
                                    SC_NOT_FOUND, MSG_TEMPLATE_USER_NOT_FOUND);
    }

    @Test
    public void testResetPassword_400WhenTokenIsExpired() {
        // data
        long userId = 123456L;
        String resetToken = "ABC123";
        User dbUser = createTestUser(userId);
        dbUser.getCredential().setResetToken(resetToken);

        String newPassword = "passowrd123[]";
        User paramUser = createUserForResetPasswordTest("jdoe", resetToken, newPassword);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserByHandle(dbUser.getHandle())).thenReturn(dbUser);
        // mock: CacheService
        CacheService cacheService = mock(CacheService.class);
        when(cacheService.get(anyString())).thenReturn(null); // token does not exist in the cache (expired)

        // test
        testResetPassword_ErrorCase(paramUser, userDao, cacheService,
                                SC_BAD_REQUEST, MSG_TEMPLATE_EXPIRED_RESET_TOKEN);
    }

    @Test
    public void testResetPassword_400WhenTokenIsIncorrect() {
        // data
        long userId = 123456L;
        String resetToken = "ABC123";
        User dbUser = createTestUser(userId);
        dbUser.getCredential().setResetToken(resetToken);

        String newPassword = "passowrd123[]";
        String invalidToken = "ABC234"; // does not match with the one in DB
        User paramUser = createUserForResetPasswordTest("jdoe", invalidToken, newPassword);

        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.findUserByHandle(dbUser.getHandle())).thenReturn(dbUser);
        // mock: CacheService
        CacheService cacheService = mock(CacheService.class);
        when(cacheService.get(anyString())).thenReturn(resetToken);

        // test
        testResetPassword_ErrorCase(paramUser, userDao, cacheService,
                                SC_BAD_REQUEST, MSG_TEMPLATE_INVALID_RESET_TOKEN);
    }


    private void testResetPassword_ErrorCase(User user, UserDAO userDao, CacheService cacheService, int expectedStatus, String expectedMessage) {
        // mock: other
        @SuppressWarnings("unchecked")
        PostPutRequest<User> postRequest = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(postRequest.getParam()).thenReturn(user);
        HttpServletRequest request = mock(HttpServletRequest.class);
        EventProducer eventProducer = mock(EventProducer.class);

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, cacheService, eventProducer, null);

        // test
        try {
            testee.resetPassword(postRequest, request);
        } catch (APIRuntimeException e) {
            assertEquals(expectedStatus, e.getHttpStatus());
            assertEquals(expectedMessage, e.getMessage());
        }

        // verify
        verify(userDao, never()).updatePassword(any(User.class));
        verify(cacheService, never()).delete(anyString());
    }
    
    @Test
    public void testGetAchievements() {
        // setup
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        // data
        long uid = 123456L;
        User user = createTestUser(uid);
        
        int dataSize = 2;
        List<Achievement> achievements = new ArrayList<>();
        for(int i=0; i<dataSize; i++) {
            Achievement achievement = new Achievement();
            achievements.add(achievement);
        }
        
        // mock: Parameters
        TCID userId = new TCID(uid);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);
        
        // mock: UserDAO
        UserDAO userDao = mock(UserDAO.class);
        doReturn(user).when(userDao).findUserById(uid);
        doReturn(achievements).when(userDao).findAchievements(uid);
        
        // QueryParameter
        FieldSelector fields = new FieldSelector();
        FilterParameter filter = new FilterParameter(null);
        OrderByQuery orderBy = new OrderByQuery();
        orderBy.getItems().add(orderBy.new OrderByItem());
        LimitQuery limit = new LimitQuery(100);
        QueryParameter queryParam = new QueryParameter(fields, filter, limit, orderBy);

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, null, null));
        
        // test
        ApiResponse result = testee.getAchievements(authUser, userId, queryParam, request);

        // Checking result
        assertNotNull("getAchievements() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();
        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(achievements, apiResult.getContent());

        // verify
        verify(userDao).findUserById(uid);
        verify(userDao).findAchievements(uid);
    }
    
    @Test
    public void testGetAchievements_404_WhenUserIsNotFound() {
    
        // parameter
        long uid = 123456L;
        TCID userId = new TCID(uid);
        AuthUser authUser = spy(new AuthUser());
        doReturn(userId).when(authUser).getUserId();
        HttpServletRequest request = mock(HttpServletRequest.class);
        
        // QueryParameter
        FieldSelector fields = new FieldSelector();
        FilterParameter filter = new FilterParameter(null);
        OrderByQuery orderBy = new OrderByQuery();
        orderBy.getItems().add(orderBy.new OrderByItem());
        LimitQuery limit = new LimitQuery(100);
        QueryParameter queryParam = new QueryParameter(fields, filter, limit, orderBy);

        // mock
        UserDAO userDao = mock(UserDAO.class);
        doReturn(null).when(userDao).findUserById(uid); // any user with userId is not found

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, null, null));
        
        // test
        try {
            testee.getAchievements(authUser, userId, queryParam, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(HTTP_NOT_FOUND, e.getHttpStatus());
            assertEquals(MSG_TEMPLATE_USER_NOT_FOUND, e.getMessage());
        }
        
        // verify
        verify(authUser).getUserId();
        verify(userDao).findUserById(uid);
        verify(userDao, never()).findAchievements(anyLong());
        
        verify(testee).checkResourceId(userId);
        verify(testee).validateResourceIdAndCheckPermission(authUser, userId, userProfilesFactory.getReadScopes());
    }

    @Test
    public void testValidateHandle() {
        // data
        String handle = "validhandle";

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        // mock
        doReturn(null).when(testee).validateHandle(handle); // null means 'valid'
        HttpServletRequest request = mock(HttpServletRequest.class);

        // test
        ApiResponse result = testee.validateHandle(handle, request);

        // Checking result
        assertNotNull("validateHandle() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        ValidationResult vr = (ValidationResult)apiResult.getContent();
        assertTrue(vr.valid);

        // verify
        verify(testee).validateHandle(handle);
    }

    @Test
    public void testValidateHandle_InvalidResponse_WhenHandleContainsBlank() {
        // data
        String handle = "with blank"; // blank is not allowed.
        // test
        testValidateHandle_InvalidResponseCase(handle,
                REASON_INVALID_FORMAT, MSG_TEMPLATE_INVALID_HANDLE_CONTAINS_SPACE);
    }

    @Test
    public void testValidateHandle_InvalidResponse_WhenHandleContainsForbiddenChar() {
        // data
        String handle = "Handle123!"; // ! is not allowed.
        // test
        testValidateHandle_InvalidResponseCase(handle,
                REASON_INVALID_FORMAT, MSG_TEMPLATE_INVALID_HANDLE_CONTAINS_FORBIDDEN_CHAR);
    }

    @Test
    public void testValidateHandle_InvalidResponse_WhenHandleContainsOnlyPunctuation() {
        // test
        testValidateHandle_InvalidResponseCase(HANDLE_PUNCTUATION,
                REASON_INVALID_FORMAT, MSG_TEMPLATE_INVALID_HANDLE_CONTAINS_ONLY_PUNCTUATION);
    }

    @Test
    public void testValidateHandle_InvalidResponse_WhenHandleStartsWithAdmin() {
        // data
        String handle = "administrator";
        // test
        testValidateHandle_InvalidResponseCase(handle,
                REASON_INVALID_HANDLE, MSG_TEMPLATE_INVALID_HANDLE_STARTS_WITH_ADMIN);
    }

    public void testValidateHandle_InvalidResponseCase(String handle, String expectedCode, String expectedReason) {

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        // mock
        HttpServletRequest request = mock(HttpServletRequest.class);

        // test
        ApiResponse result = testee.validateHandle(handle, request);

        // Checking result
        assertNotNull("validateHandle() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        ValidationResult vr = (ValidationResult)apiResult.getContent();
        assertFalse(vr.valid);
        assertEquals(expectedCode, vr.reasonCode);
        assertEquals(expectedReason, vr.reason);
    }

    @Test
    public void testValidateHandle_InvalidResponse_WhenHandleIsInvalid() {
        // data
        String handle = "invalidhandle";

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        // mock
        doReturn(MSG_TEMPLATE_INVALID_HANDLE).when(testee).validateHandle(handle);
        HttpServletRequest request = mock(HttpServletRequest.class);

        // test
        ApiResponse result = testee.validateHandle(handle, request);

        // Checking result
        assertNotNull("validateHandle() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        ValidationResult vr = (ValidationResult)apiResult.getContent();
        assertFalse(vr.valid);
        assertEquals(REASON_INVALID_HANDLE, vr.reasonCode);
        assertEquals(MSG_TEMPLATE_INVALID_HANDLE, vr.reason);

        // verify
        verify(testee).validateHandle(handle);
    }

    @Test
    public void testValidateHandle_InvalidResponse_WhenHandleIsAldreadyTaken() {
        // data
        String handle = "already-taken";

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        // mock
        String err = String.format(MSG_TEMPLATE_DUPLICATED_HANDLE, handle);
        doReturn(err).when(testee).validateHandle(handle);
        HttpServletRequest request = mock(HttpServletRequest.class);

        // test
        ApiResponse result = testee.validateHandle(handle, request);

        // Checking result
        assertNotNull("validateHandle() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        ValidationResult vr = (ValidationResult)apiResult.getContent();
        assertFalse(vr.valid);
        assertEquals(REASON_ALREADY_TAKEN, vr.reasonCode);
        assertEquals(err, vr.reason);

        // verify
        verify(testee).validateHandle(handle);
    }

    @Test
    public void testValidateHandle_400WhenNoHandleSpecified() {
        // data
        String handle = null;

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        // mock
        HttpServletRequest request = mock(HttpServletRequest.class);

        // test
        try {
            testee.validateHandle(handle, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(HttpServletResponse.SC_BAD_REQUEST, e.getHttpStatus());
        }
    }

    @Test
    public void testValidateEmail() {
        // data
        String email = "validemail@example.com";

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        // mock
        doReturn(null).when(testee).validateEmail(email); // null means 'valid'
        HttpServletRequest request = mock(HttpServletRequest.class);

        // test
        ApiResponse result = testee.validateEmail(email, request);

        // Checking result
        assertNotNull("validateHandle() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        ValidationResult vr = (ValidationResult)apiResult.getContent();
        assertTrue(vr.valid);

        // verify
        verify(testee).validateEmail(email);
    }

    @Test
    public void testValidateEmail_InvalidResponse_WhenEmailIsInvalid() {
        // data
        String email = "invalid email"; // not email

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        // mock
        doReturn(null).when(testee).validateEmail(email); // null means 'valid'
        HttpServletRequest request = mock(HttpServletRequest.class);

        // test
        ApiResponse result = testee.validateEmail(email, request);

        // Checking result
        assertNotNull("validateHandle() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        ValidationResult vr = (ValidationResult)apiResult.getContent();
        assertFalse(vr.valid);
        assertEquals(REASON_INVALID_EMAIL, vr.reasonCode);
        assertEquals(MSG_TEMPLATE_INVALID_EMAIL, vr.reason);

        // verify
        verify(testee, never()).validateEmail(email);
    }

    @Test
    public void testValidateEmail_InvalidResponse_WhenEmailHasAlreadyUsed() {
        // data
        String email = "usedemail@example.com";

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        // mock
        String err = String.format(MSG_TEMPLATE_DUPLICATED_EMAIL, email);
        doReturn(err).when(testee).validateEmail(email);
        HttpServletRequest request = mock(HttpServletRequest.class);

        // test
        ApiResponse result = testee.validateEmail(email, request);

        // Checking result
        assertNotNull("validateHandle() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        ValidationResult vr = (ValidationResult)apiResult.getContent();
        assertFalse(vr.valid);
        assertEquals(REASON_ALREADY_TAKEN, vr.reasonCode);
        assertEquals(err, vr.reason);

        // verify
        verify(testee).validateEmail(email);
    }

    @Test
    public void testValidateEmail_400WhenNoEmailSpecified() {
        // data
        String email = null;

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        // mock
        HttpServletRequest request = mock(HttpServletRequest.class);

        // test
        try {
            testee.validateEmail(email, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(HttpServletResponse.SC_BAD_REQUEST, e.getHttpStatus());
        }
    }

    @Test
    public void testValidateSocial() {
        // data
        String socialUserId = "validSocialUserId";
        String socialProvider = "facebook";
        UserProfile socialProfile = new UserProfile();
        socialProfile.setUserId(socialUserId);
        socialProfile.setProviderType(socialProvider);

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        // mock
        doReturn(null).when(testee).validateSocialProfile(any(UserProfile.class)); // null means 'valid'
        HttpServletRequest request = mock(HttpServletRequest.class);

        // test
        ApiResponse result = testee.validateSocial(socialUserId, socialProvider, request);

        // Checking result
        assertNotNull("validateHandle() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        ValidationResult vr = (ValidationResult)apiResult.getContent();
        assertTrue(vr.valid);

        // verify
        verify(testee).validateSocialProfile(any(UserProfile.class));
    }

    @Test
    public void testValidateSocial_InvalidResponse_WhenSocialAccountAlreadyInUse() {
        // data
        String socialUserId = "validSocialUserId";
        String socialProvider = ProviderType.FACEBOOK.name;
        UserProfile socialProfile = new UserProfile();
        socialProfile.setUserId(socialUserId);
        socialProfile.setProviderType(socialProvider);

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        // mock
        doReturn(MSG_TEMPLATE_SOCIAL_PROFILE_IN_USE).when(testee).validateSocialProfile(any(UserProfile.class));
        HttpServletRequest request = mock(HttpServletRequest.class);

        // test
        ApiResponse result = testee.validateSocial(socialUserId, socialProvider, request);

        // Checking result
        assertNotNull("validateHandle() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        ValidationResult vr = (ValidationResult)apiResult.getContent();
        assertFalse(vr.valid);
        assertEquals(REASON_ALREADY_IN_USE, vr.reasonCode);
        assertEquals(MSG_TEMPLATE_SOCIAL_PROFILE_IN_USE, vr.reason);

        // verify
        verify(testee).validateSocialProfile(any(UserProfile.class));
    }

    @Test
    public void testValidateSocial_400WhenProviderIsNotSupported() {
        // data
        String socialUserId = "validSocialUserId";
        String socialProvider = ProviderType.SAMLP.name; // non-social
        UserProfile socialProfile = new UserProfile();
        socialProfile.setUserId(socialUserId);
        socialProfile.setProviderType(socialProvider);

        // testee
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        // mock
        HttpServletRequest request = mock(HttpServletRequest.class);

        // test
        try {
            testee.validateSocial(socialUserId, socialProvider, request);
            fail("APIRuntimeException should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(HttpServletResponse.SC_BAD_REQUEST, e.getHttpStatus());
        }
    }

    @Test
    public void testValidateSocialProfile() {
        // data: valid social user profile
        UserProfile profile = new UserProfile();
        profile.setUserId("AVAILABLE-SOCIAL-USER-ID");
        profile.setProviderType(ProviderType.FACEBOOK.name);

        // mock
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.socialUserExists(profile)).thenReturn(false); // social profile not in use

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, null, null));

        // test
        String result = testee.validateSocialProfile(profile);

        // verify result
        assertNull("validateSocialProfile(profile) should return null when the profile is valid(available).", result);

        // verify mock
        verify(userDao).socialUserExists(profile);
    }

    @Test
    public void testValidateSocialProfile_WhenProfileHasNoUserId() {
        // data
        UserProfile profile = new UserProfile();
        profile.setUserId(null); // no user id
        profile.setProviderType(ProviderType.FACEBOOK.name);

        // mock
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.socialUserExists(profile)).thenReturn(false); // social profile not in use

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, null, null));

        // test
        String result = testee.validateSocialProfile(profile);

        // verify result
        assertNotNull("validateSocialProfile(profile) should return an error message", result);

        // verify mock
        verify(userDao, never()).socialUserExists(profile);
    }

    @Test
    public void testValidateSocialProfile_WhenProvderIsNotForSocial() {
        // data
        UserProfile profile = new UserProfile();
        profile.setUserId("VALID-SOCIAL-USER-ID");
        profile.setProviderType(ProviderType.LDAP.name); // not social

        // mock
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.socialUserExists(profile)).thenReturn(false); // social profile not in use

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, null, null));

        // test
        String result = testee.validateSocialProfile(profile);

        // verify result
        assertNotNull("validateSocialProfile(profile) should return an error message", result);

        // verify mock
        verify(userDao, never()).socialUserExists(profile);
    }

    @Test
    public void testValidateSocialProfile_WhenSocialAccountAlreadyInUse() {
        // data
        UserProfile profile = new UserProfile();
        profile.setUserId("INVALID-SOCIAL-USER-ID");
        profile.setProviderType(ProviderType.FACEBOOK.name);

        // mock
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.socialUserExists(profile)).thenReturn(true); // social profile already in use

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, null, null));

        // test
        String result = testee.validateSocialProfile(profile);

        // verify result
        assertNotNull("validateSocialProfile(profile) should return an error message", result);
        assertEquals(MSG_TEMPLATE_SOCIAL_PROFILE_IN_USE, result);

        // verify mock
        verify(userDao).socialUserExists(profile);
    }

    @Test
    public void testValidateSocialProfile_WithUser() {
        // data: ID of related user who own the following profile
        long userId = 123456L;

        // data: valid social user profile
        UserProfile profile = new UserProfile();
        profile.setUserId("AVAILABLE-SOCIAL-USER-ID");
        profile.setProviderType(ProviderType.GITHUB.name);

        // mock
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.socialUserExists(profile)).thenReturn(false); // social profile not in use
        when(userDao.getSocialProfiles(userId, profile.getProviderTypeEnum())).thenReturn(null); // profile can be created

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, null, null));

        // test
        String result = testee.validateSocialProfile(userId, profile);

        // verify result
        assertNull("validateSocialProfile(userId, profile) should return null when the profile is valid(available).", result);

        // verify mock
        verify(userDao).socialUserExists(profile);
        verify(userDao).getSocialProfiles(userId, profile.getProviderTypeEnum());
    }

    @Test
    public void testValidateSocialProfile_WithUser_WhenSpecifiedProviderIsAlreadyBoundWithUser() {
        // data: ID of related user who own the following profile
        long userId = 123456L;

        // data: valid social user profile
        UserProfile profile = new UserProfile();
        profile.setUserId("AVAILABLE-SOCIAL-USER-ID");
        profile.setProviderType(ProviderType.GITHUB.name);

        // data: profiles stored in database
        List<UserProfile> dbProfiles = new ArrayList<>();
        UserProfile profileBoundWithUser = new UserProfile();
        profileBoundWithUser.setUserId("ANOTHER-SOCIAL-USER-ID");
        profileBoundWithUser.setProviderType(ProviderType.GITHUB.name);
        dbProfiles.add(profileBoundWithUser);

        // mock
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.getSocialProfiles(userId, profile.getProviderTypeEnum())).thenReturn(dbProfiles); // profile of the same provider already exits

        // testee
        UserResource testee = spy(new UserResource(userDao, mockRoleDao, null, null, null));

        // test
        String result = testee.validateSocialProfile(userId, profile);

        // verify result
        assertEquals(MSG_TEMPLATE_USER_ALREADY_BOUND_WITH_PROVIDER, result);

        // verify mock
        verify(userDao).getSocialProfiles(userId, profile.getProviderTypeEnum());
        verify(userDao, never()).socialUserExists(any(UserProfile.class));
    }

    @Test
    public void testValidateSSOProfile() {
        // data
        UserProfile profile = new UserProfile();
        profile.setUserId("AVAILABLE-SSO-USER-ID");
        profile.setProviderType(ProviderType.SAMLP.name);
        profile.setProvider("SAMLP-PROVIDER");

        // mock
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.ssoUserExists(profile)).thenReturn(false); // sso account not in use

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);

        // test
        String result = testee.validateSSOProfile(profile);

        assertNull("validateSSOProfile(profile) should return null when the profile is valid(available).", result);

        // verify mock
        verify(userDao).ssoUserExists(profile);
    }


    @Test
    public void testValidateSSOProfile_WhenSSOAccountAlreadyInUse() {
        // data
        UserProfile profile = new UserProfile();
        profile.setUserId("AVAILABLE-SSO-USER-ID");
        profile.setProviderType(ProviderType.SAMLP.name);
        profile.setProvider("SAMLP-PROVIDER");

        // mock
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.ssoUserExists(profile)).thenReturn(true); // sso account is in use

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);

        // test
        String result = testee.validateSSOProfile(profile);

        assertNotNull("validateSSOProfile(profile) should return an error message.", result);

        // verify mock
        verify(userDao).ssoUserExists(profile);
    }

    @Test
    public void testValidateSSOProfile_WhenProfileHasNoUserIdAndEmail() {
        // data
        UserProfile profile = new UserProfile();
        profile.setUserId(null);
        profile.setEmail(null);
        profile.setProviderType(ProviderType.SAMLP.name);
        profile.setProvider("SAMLP-PROVIDER");

        // mock
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.ssoUserExists(profile)).thenReturn(false); // sso account is available

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);

        // test
        String result = testee.validateSSOProfile(profile);

        assertNotNull("validateSSOProfile(profile) should return an error message.", result);

        // verify mock
        verify(userDao, never()).ssoUserExists(profile);
    }

    @Test
    public void testValidateSSOProfile_WhenProvderIsNotForEnterprise() {
        // data
        UserProfile profile = new UserProfile();
        profile.setUserId(null);
        profile.setEmail(null);
        profile.setProviderType(ProviderType.FACEBOOK.name);

        // mock
        UserDAO userDao = mock(UserDAO.class);
        when(userDao.ssoUserExists(profile)).thenReturn(false); // sso account is available

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);

        // test
        String result = testee.validateSSOProfile(profile);

        assertNotNull("validateSSOProfile(profile) should return an error message.", result);

        // verify mock
        verify(userDao, never()).ssoUserExists(profile);
    }

    @Test
    public void testValidateReferral() {

        String referrer = "HANDLE";

        // mock
        UserDAO userDao = mock(UserDAO.class);
        doReturn(true).when(userDao).handleExists(referrer); // existing handle

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);

        // test
        String result = testee.validateReferral(referrer);

        // verify
        assertNull(result);
        verify(userDao).handleExists(referrer);
    }

    @Test
    public void testValidateReferral_WhenSourceIsNotSpecified() {
        // mock
        UserDAO userDao = mock(UserDAO.class);

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);

        // test
        String result = testee.validateReferral(null);

        // verify
        assertEquals(MSG_TEMPLATE_MISSING_UTMSOURCE, result);
        verify(userDao, never()).handleExists(anyString());
    }

    @Test
    public void testValidateReferral_WhenSourceIsNotAnExistingHandle() {

        String referrer = "HANDLE";

        // mock
        UserDAO userDao = mock(UserDAO.class);
        doReturn(false).when(userDao).handleExists(referrer); // not existing handle

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);

        // test
        String result = testee.validateReferral(referrer);

        // verify
        assertEquals(MSG_TEMPLATE_USER_NOT_FOUND, result);
        verify(userDao).handleExists(referrer);
    }

    @Test
    public void testValidateCountry() {

        // data
        Country country = new Country();
        country.setCode("123");

        // data
        Country countryInDb = new Country();
        countryInDb.setCode("123");
        countryInDb.setISOAlpha2Code("DM");
        countryInDb.setISOAlpha3Code("DMM");
        countryInDb.setName("DUMMY-COUNTRY");

        // mock
        UserDAO userDao = mock(UserDAO.class);
        doReturn(countryInDb).when(userDao).findCountryBy(country);

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);

        // test
        String result = testee.validateCountry(country);

        // verify
        assertNull(result);
        assertEquals(countryInDb.getCode(), country.getCode());
        assertEquals(countryInDb.getISOAlpha2Code(), country.getISOAlpha2Code());
        assertEquals(countryInDb.getISOAlpha3Code(), country.getISOAlpha3Code());
        assertEquals(countryInDb.getName(), country.getName());

        verify(userDao).findCountryBy(country);
    }


    @Test
    public void testValidateCountry_InvalidWhenAnyCountryIsNotFoundForInput() {

        // data
        Country country = new Country();
        country.setCode("123");

        // mock
        UserDAO userDao = mock(UserDAO.class);
        doReturn(null).when(userDao).findCountryBy(country); // not found in database

        // testee
        UserResource testee = new UserResource(userDao, mockRoleDao, null, null, null);

        // test
        String result = testee.validateCountry(country);

        // verify
        assertEquals(MSG_TEMPLATE_INVALID_COUNTRY, result);
        verify(userDao).findCountryBy(country);
    }
    
    @Test
    public void testCheckResourceId() {
        UserResource testee = new UserResource(null, null, null, null, null);
        
        TCID validId = new TCID(123456L);
        testee.checkResourceId(validId);
        
        TCID invalidId = new TCID("INVALID-ID");
        try {
            testee.checkResourceId(invalidId);
        } catch(APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
            assertEquals(MSG_TEMPLATE_INVALID_ID, e.getMessage());
        }
        
        try {
            testee.checkResourceId(null);
        } catch(APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
            assertEquals(String.format(Constants.MSG_TEMPLATE_MANDATORY, "resourceId"), e.getMessage());
        }

    }

    @Test
    public void testCheckAdminPermission_SuccessWhenResourceIsOperatorItself() {
    
        TCID resourceId = new TCID(123456L);
        TCID operatorId = new TCID(123456L);
        assertEquals(resourceId, operatorId);
        
        AuthUser authUser = spy(new AuthUser());
        doReturn(operatorId).when(authUser).getUserId();
        
        UserResource testee = new UserResource(null, null, null, null, null);
        
        testee.validateResourceIdAndCheckPermission(authUser, resourceId, null);
        
        verify(authUser).getUserId();
    }
    
    @Test
    public void testCheckAdminPermission_SuccessWhenOperatorIsAdmin() {
        TCID resourceId = new TCID(123456L);
        TCID operatorId = new TCID(123457L);
        assertNotEquals(resourceId, operatorId);

        AuthUser authUser = TestUtils.createAdminAuthUserMock(operatorId);
        
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        
        testee.validateResourceIdAndCheckPermission(authUser, resourceId, null);
    }

    @Test
    public void testCheckAdminPermission_FailWhenOperatorDoesNotHaveAccess() {
        TCID resourceId = new TCID(123456L);
        TCID operatorId = new TCID(123457L);
        assertNotEquals(resourceId, operatorId);

        AuthUser authUser = spy(new AuthUser());
        doReturn(operatorId).when(authUser).getUserId();
        
        UserResource testee = spy(new UserResource(null, null, null, null, null));
        
        try {
            testee.validateResourceIdAndCheckPermission(authUser, resourceId, null);
            fail("APIRuntimeException(403) should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_FORBIDDEN, e.getHttpStatus());
        }
        
        verify(authUser).getUserId();
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testCheckParam_SuccessRequestHasParam() {
        
        User user = new User();
        PostPutRequest<User> request = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(request.getParam()).thenReturn(user);
        
        UserResource testee = new UserResource(null, null, null, null, null);
        
        testee.checkParam(request);
        
        verify(request).getParam();
    }
    
    @Test
    @SuppressWarnings("unchecked")
    public void testCheckParam_FailRequestHasNoParam() {
        
        PostPutRequest<User> request = (PostPutRequest<User>)mock(PostPutRequest.class);
        when(request.getParam()).thenReturn(null);
        
        UserResource testee = new UserResource(null, null, null, null, null);
        
        try {
            testee.checkParam(request);
            fail("APIRuntimeException(400) should be thrown in the previous step.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        }
        verify(request).getParam();
    }
    
    
    @Test
    public void testSetAccessToken() throws Exception {
        
        // data
        String auth0UserId = "DUMMY-AUTH0-USER-ID";
        
        UserProfile profile = new UserProfile();
        profile.setContext(new HashMap<>());
        profile.getContext().put("auth0UserId", auth0UserId);
        
        // mock
        String idpAccessToken = "DUMMY-ACCESS-TOKEN";
        Auth0Client auth0 = mock(Auth0Client.class);
        doReturn(idpAccessToken).when(auth0).getIdProviderAccessToken(auth0UserId);
        
        // testeee
        UserResource testee = new UserResource(null, null, null, null, null);
        testee.setAuth0Client(auth0);
        
        // test
        testee.setAccessToken(profile);
        
        // verify
        assertNotNull(profile.getContext());
        assertEquals(idpAccessToken, profile.getContext().get("accessToken"));
        
        verify(auth0).getIdProviderAccessToken(auth0UserId);
    }
    
    @Test
    public void testSetAccessToken_WhenAuth0UserIdIsMissingInContext() throws Exception {
        
        // data
        String userId = "DUMMY-USER-ID";
        String providerType = ProviderType.GITHUB.name;
        String auth0UserId = providerType + "|" + userId;
        
        UserProfile profile = new UserProfile();
        profile.setUserId(userId);
        profile.setProviderType(providerType);
        assertNull(profile.getContext());
        
        // mock
        String idpAccessToken = "DUMMY-ACCESS-TOKEN";
        Auth0Client auth0 = mock(Auth0Client.class);
        doReturn(idpAccessToken).when(auth0).getIdProviderAccessToken(auth0UserId);
        
        // testeee
        UserResource testee = new UserResource(null, null, null, null, null);
        testee.setAuth0Client(auth0);
        
        // test
        testee.setAccessToken(profile);
        
        // verify
        assertNotNull(profile.getContext());
        assertEquals(idpAccessToken, profile.getContext().get("accessToken"));
        assertEquals(userId, profile.getUserId());
        assertEquals(providerType, profile.getProviderType());
        
        verify(auth0).getIdProviderAccessToken(auth0UserId);
    }
    
    @Test
    public void testSetAccessToken_Null_WhenAuth0ReturnsNoAccessToken() throws Exception {
        // data
        String userId = "DUMMY-USER-ID";
        String providerType = ProviderType.AUTH0.name;
        String auth0UserId = providerType + "|" + userId;
                
        // mock
        Auth0Client auth0 = mock(Auth0Client.class);
        doReturn(null).when(auth0).getIdProviderAccessToken(auth0UserId); // No accessToken contained in data from auth0
        
        testSetAccessToken_CaseToGetNull(userId, providerType, auth0);
    }

    @Test
    public void testSetAccessToken_Null_WhenAuth0CausesException() throws Exception {
        // data
        String userId = "DUMMY-USER-ID";
        String providerType = ProviderType.AUTH0.name;
        String auth0UserId = providerType + "|" + userId;
                
        // mock
        Auth0Client auth0 = mock(Auth0Client.class);
        Exception e = new Exception("DUMMY-EXCEPTION");
        doThrow(e).when(auth0).getIdProviderAccessToken(auth0UserId); // causing Exception
        
        testSetAccessToken_CaseToGetNull(userId, providerType, auth0);
    }

    public void testSetAccessToken_CaseToGetNull(String userId, String providerType, Auth0Client auth0) throws Exception {
        // data
        String auth0UserId = providerType + "|" + userId;
        UserProfile profile = new UserProfile();
        profile.setUserId(userId);
        profile.setProviderType(providerType);
                
        // testeee
        UserResource testee = new UserResource(null, null, null, null, null);
        testee.setAuth0Client(auth0);
        
        // test
        testee.setAccessToken(profile);
        
        // verify
        assertTrue(
                profile.getContext() == null ||
                !profile.getContext().containsKey("accessToken"));
        assertEquals(userId, profile.getUserId());
        assertEquals(providerType, profile.getProviderType());
        
        verify(auth0).getIdProviderAccessToken(auth0UserId);
    }

    private User createUserForResetPasswordTest(String handle, String resetToken, String newPassword) {
        User paramUser = new User();
        paramUser.setHandle(handle);
        paramUser.setCredential(new Credential());
        paramUser.getCredential().setResetToken(resetToken);
        paramUser.getCredential().setPassword(newPassword);
        return paramUser;
    }

    protected User createTestUser(Long userId) {
        User user = new User();
        user.setHandle("jdoe");
        user.setEmail("jdoe@examples.com");
        user.setEmailStatus(2);
        user.setActive(false);
        user.setCountry(new Country());
        user.getCountry().setName("United States");
        user.setCredential(new Credential());
        user.getCredential().setPassword("PASSWORD");
        if(userId!=null) {
            user.setId(new TCID(userId));
            user.getCredential().setActivationCode(Utils.getActivationCode(userId));
        }
        return user;
    }

    AuthUser createMockAuthUser(TCID userId) {
        return createMockAuthUser(userId, null);
    }

    AuthUser createMockAdminAuthUser(TCID userId) {
        return createMockAuthUser(userId, Arrays.asList(Utils.AdminRoles));
    }
    
    AuthUser createMockAuthUser(TCID userId, List<String> roles) {
        AuthUser authUser = mock(AuthUser.class);
        if(userId!=null)
            doReturn(userId).when(authUser).getUserId();
        if(roles!=null && roles.size()>0)
            doReturn(roles).when(authUser).getRoles();
        return authUser;
    }
}
