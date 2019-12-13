package com.appirio.tech.core.service.identity.dao;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;
import io.dropwizard.jackson.Jackson;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.BeforeClass;
import org.junit.Test;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.dropwizard.APIApplication;
import com.appirio.tech.core.api.v3.model.ResourceHelper;
import com.appirio.tech.core.api.v3.request.FieldSelector;
import com.appirio.tech.core.api.v3.request.FilterParameter;
import com.appirio.tech.core.api.v3.request.LimitQuery;
import com.appirio.tech.core.api.v3.request.OrderByQuery.OrderByItem;
import com.appirio.tech.core.service.identity.dao.ExternalAccountDAO.ExternalAccount;
import com.appirio.tech.core.service.identity.representation.Country;
import com.appirio.tech.core.service.identity.representation.Credential;
import com.appirio.tech.core.service.identity.representation.Email;
import com.appirio.tech.core.service.identity.representation.UserProfile;
import com.appirio.tech.core.service.identity.representation.ProviderType;
import com.appirio.tech.core.service.identity.representation.User;
import com.appirio.tech.core.service.identity.util.Constants;
import com.appirio.tech.core.service.identity.util.Utils;
import com.appirio.tech.core.service.identity.util.Utils.NumberTrimmingTokenExtractor;
import com.appirio.tech.core.service.identity.util.Utils.RegexTokenExtractor;
import com.appirio.tech.core.service.identity.util.Utils.TokenExtractor;
import com.appirio.tech.core.service.identity.util.idgen.SequenceDAO;
import com.appirio.tech.core.service.identity.util.ldap.LDAPService;
import com.appirio.tech.core.service.identity.util.ldap.MemberStatus;

/**
 * Test UserDAO
 * 
 * <p>
 * Changes in the version 1.1 72h TC Identity Service API Enhancements v1.0
 * - add tests for populateById
 * </p>
 * 
 * @author TCCoder
 * @version 1.1
 *
 */
public class UserDAOTest {
	
	@BeforeClass
	public static void setupBeforeClass() {
		APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();
	}
	
	
	@Test
	public void testFindUserByEmail() throws Exception {
		//data
		long userId = 123456L;
		User user = createTestUser(userId);
		assertNotNull(user.getEmail());
		List<User> users = new ArrayList<User>();
		users.add(user);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).findUserByEmail(user.getEmail());
		
		//mock
		doReturn(users).when(testee).findUsersByEmail(user.getEmail());
		
		//test
		User result = testee.findUserByEmail(user.getEmail());
		
		// verify
		assertNotNull(result);
		assertEquals(user, result);
		
		verify(testee).findUsersByEmail(user.getEmail());
	}
	
	@Test
	public void testFindUserByEmail_DoExactMatch_WhenMultipleUsersFoundWithEmail() throws Exception {
		//data
		String email = "jdoe@appirio.com";
		long[] userIds   = new long[]{123456L, 123457L, 123458L};
		String[] handles = new String[]{"HANDLE-A", "HANDLE-B", "HANDLE-C"};
		String[] emails  = new String[]{"jDoe@appirio.com", email, "jdoe@Appirio.Com"};
		List<User> users = new ArrayList<User>();
		for(int i=0; i<userIds.length; i++) {
			User user = createTestUser(userIds[i]);
			user.setHandle(handles[i]);
			user.setEmail(emails[i]);
			users.add(user);
		}
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).findUserByEmail(email);
		
		//mock
		doReturn(users).when(testee).findUsersByEmail(email);
		
		//test
		User result = testee.findUserByEmail(email);
		
		// verify
		assertNotNull(result);
		assertEquals(email, result.getEmail());
		assertEquals(users.get(1), result);
		
		verify(testee).findUsersByEmail(email);
	}
	
	@Test
	public void testFindUserByEmail_FirstOne_WhenMultipleUsersFoundWithEmailAndNothingMatched() throws Exception {
		//data
		String email = "jdoe@appirio.com";
		long[] userIds   = new long[]{123456L, 123457L, 123458L};
		String[] handles = new String[]{"HANDLE-A", "HANDLE-B", "HANDLE-C"};
		String[] emails  = new String[]{"jDoe@appirio.com", "JDOE@APPIRIO.COM", "jdoe@Appirio.Com"};
		List<User> users = new ArrayList<User>();
		for(int i=0; i<userIds.length; i++) {
			User user = createTestUser(userIds[i]);
			user.setHandle(handles[i]);
			user.setEmail(emails[i]);
			users.add(user);
		}
		for (User user : users) {
			assertNotEquals(user.getEmail(), email);
		}

		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).findUserByEmail(email);
		
		//mock
		doReturn(users).when(testee).findUsersByEmail(email);
		
		//test
		User result = testee.findUserByEmail(email);
		
		// verify
		assertNotNull(result);
		assertEquals(users.get(0), result);
		
		verify(testee).findUsersByEmail(email);
	}
	
	@SuppressWarnings("unchecked")
	@Test
	public void testFindUsers() {
		// parameters
		FilterParameter filterParam = new FilterParameter(null);
		List<OrderByItem> orders = new ArrayList<OrderByItem>();
		LimitQuery limit = new LimitQuery(null);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).findUsers(any(FilterParameter.class), any(List.class), any(LimitQuery.class));

		// mock
		User paramUser = new User();
		doReturn(paramUser).when(testee).createEmptyUserForSearchCondition();
		String whereClause = "WHERE DUMMY = :dummy";
		doReturn(whereClause).when(testee).buildWhereClause(filterParam, paramUser);
		String offsetClause = "SKIP DUMMY";
		doReturn(offsetClause).when(testee).buildOffsetClause(limit);
		String limitClause = "FIRST DUMMY";
		doReturn(limitClause).when(testee).buildLimitClause(limit);
		String joinOnEmail = "INNER JOIN";
		doReturn(joinOnEmail).when(testee).buildJoinOnEmail(filterParam);
		
		List<User> foundUsers = new ArrayList<User>();
		doReturn(foundUsers).when(testee).findUsers(paramUser, joinOnEmail, whereClause, null, offsetClause, limitClause);
		
		// test
		List<User> result = testee.findUsers(filterParam, orders, limit);
		
		// verify result
		assertEquals(foundUsers, result);
		
		// verify that methods have been invoked as expected 
		verify(testee).createEmptyUserForSearchCondition();
		verify(testee).buildWhereClause(filterParam, paramUser);
		verify(testee).buildOffsetClause(limit);
		verify(testee).buildLimitClause(limit);
		verify(testee).findUsers(paramUser, joinOnEmail, whereClause, null, offsetClause, limitClause);
	}
	
	@Test
	public void testBuildLimitClause() throws Exception {
		// parameters
		LimitQuery limit = new LimitQuery(100);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).buildLimitClause(any(LimitQuery.class));

		// test
		String result = testee.buildLimitClause(limit);
		
		// verify result
		assertEquals(String.format("FIRST %d",limit.getLimit()), result);
	}

	@Test
	public void testBuildLimitClause_WithDefaultValue() throws Exception {
		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).buildLimitClause(any(LimitQuery.class));

		// test
		String result = testee.buildLimitClause(null);
		
		// verify result
		assertEquals(String.format("FIRST %d", UserDAO.DEFAULT_LIMIT), result);
	}
	
	@Test
	public void testBuildLimitClause_IAE_WhenLimitIsNotPositive() throws Exception {
		int[] testValues = new int[]{ 0, -1 };
		for(int i=0; i<testValues.length; i++) {

			// parameters
			LimitQuery limit = new LimitQuery(testValues[i]);
			
			//testee
			UserDAO testee = mock(UserDAO.class);
			doCallRealMethod().when(testee).buildLimitClause(any(LimitQuery.class));
	
			// test
			try {
				testee.buildLimitClause(limit);
				fail("IllegalArgumentException should be thrown in the previous step.");
			} catch (IllegalArgumentException e) {
			}
		}
	}
	
	@Test
	public void testBuildWhereClause_WithAllSupportedItems() throws Exception {
		// parameters
		User paramUser = new User();
		String id = "123456";
		String handle = "DUMMY-HANDLE";
		String email = "DUMMY-EMAIL";
		boolean active = true;
		FilterParameter filterParam = new FilterParameter(null);
		filterParam.put("id", id);
		filterParam.put("handle", handle);
		filterParam.put("email", email);
		filterParam.put("active", active);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createQueryHelper();
		doCallRealMethod().when(testee).populate(paramUser, filterParam.getParamMap());
		doCallRealMethod().when(testee).buildWhereClause(filterParam, paramUser);

		// test
		String whereClause = testee.buildWhereClause(filterParam, paramUser);
		
		// check result: where clause text
		assertTrue(whereClause.startsWith(" WHERE "));
		List<String> conditions = Arrays.asList(whereClause.substring(" WHERE ".length()).split(" AND "));
		for(String cond : new String[]{ "u.user_id = "+id,
										"LOWER(e.address) = LOWER(:u.email)",
										"u.status = 'A'"}) {
			assertTrue(String.format("Where clause should contain '%s' in '%s'.", cond, whereClause),
					conditions.contains(cond));
		}
		
		// check result: parameters should be set in user object 
		assertEquals(id, paramUser.getId().getId());
		assertEquals(handle, paramUser.getHandle());
		assertEquals(email, paramUser.getEmail());
		assertEquals(active, paramUser.isActive());
		
		// verify mock
		verify(testee, atLeastOnce()).createQueryHelper();
		verify(testee).populate(paramUser, filterParam.getParamMap());
	}
	
	@Test
	public void testBuildWhereClause_WithNoParameter() throws Exception {
		// parameters
		User paramUser = new User();
		FilterParameter filterParam = new FilterParameter(null);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createQueryHelper();
		doCallRealMethod().when(testee).populate(paramUser, filterParam.getParamMap());
		doCallRealMethod().when(testee).buildWhereClause(filterParam, paramUser);

		// test
		String result = testee.buildWhereClause(filterParam, paramUser);
		
		// result should be null
		assertNull(result);
	}
	
	@Test
	public void testBuildWhereClause_WithConditionOfID() throws Exception {
		// parameters
		User paramUser = new User();
		String id = "123456";
		FilterParameter filterParam = new FilterParameter(null);
		filterParam.put("id", id);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createQueryHelper();
		doCallRealMethod().when(testee).populate(paramUser, filterParam.getParamMap());
		doCallRealMethod().when(testee).buildWhereClause(filterParam, paramUser);

		// test
		String result = testee.buildWhereClause(filterParam, paramUser);
		
		// check result: where clause text
		assertEquals(result, " WHERE u.user_id = "+id);
		
		// verify mock
		verify(testee, atLeastOnce()).createQueryHelper();
		verify(testee).populate(paramUser, filterParam.getParamMap());
	}
	
	@Test
	public void testBuildWhereClause_IAE_WhenInvalidIDIsSpecifiedOnCondition() throws Exception {
		// parameters
		User paramUser = new User();
		String id = "INVALID-ID"; // should be number
		FilterParameter filterParam = new FilterParameter(null);
		filterParam.put("id", id);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createQueryHelper();
		doCallRealMethod().when(testee).populate(paramUser, filterParam.getParamMap());
		doCallRealMethod().when(testee).buildWhereClause(filterParam, paramUser);

		// test
		try {
			testee.buildWhereClause(filterParam, paramUser);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
	}

	@Test
	public void testBuildWhereClause_WithConditionOfHandle() throws Exception {
		// parameters
		User paramUser = new User();
		String handle = "DUMMY-HANDLE";
		FilterParameter filterParam = new FilterParameter(null);
		filterParam.put("handle", handle);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createQueryHelper();
		doCallRealMethod().when(testee).populate(paramUser, filterParam.getParamMap());
		doCallRealMethod().when(testee).buildWhereClause(filterParam, paramUser);

		// test
		String result = testee.buildWhereClause(filterParam, paramUser);
		
		// check result: where clause text
		assertEquals(result, " WHERE u.handle_lower = LOWER(:u.handle)");
		
		// check result: parameters should be set in user object 
		assertEquals(handle, paramUser.getHandle());
		
		// verify mock
		verify(testee, atLeastOnce()).createQueryHelper();
		verify(testee).populate(paramUser, filterParam.getParamMap());
	}

	@Test
	public void testBuildWhereClause_WithPartialMatchConditionOfHandle() throws Exception {
		// parameters
		User paramUser = new User();
		String handle = "DUMMY*HANDLE";
		FilterParameter filterParam = new FilterParameter("like=true");
		filterParam.put("handle", handle);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createQueryHelper();
		doCallRealMethod().when(testee).populate(paramUser, filterParam.getParamMap());
		doCallRealMethod().when(testee).buildWhereClause(filterParam, paramUser);

		// test
		String result = testee.buildWhereClause(filterParam, paramUser);
		
		// check result: where clause text
		assertEquals(result, " WHERE u.handle_lower like LOWER(:u.handle)");
		
		// check result: parameters should be set in user object 
		assertEquals(handle.replaceAll("\\*", "%"), paramUser.getHandle());
		
		// verify mock
		verify(testee, atLeastOnce()).createQueryHelper();
		verify(testee).populate(paramUser, filterParam.getParamMap());
	}
	
	@Test
	public void testBuildWhereClause_WithConditionOfEmail() throws Exception {
		// parameters
		User paramUser = new User();
		String email = "DUMMY-EMAIL";
		FilterParameter filterParam = new FilterParameter(null);
		filterParam.put("email", email);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createQueryHelper();
		doCallRealMethod().when(testee).populate(paramUser, filterParam.getParamMap());
		doCallRealMethod().when(testee).buildWhereClause(filterParam, paramUser);

		// test
		String result = testee.buildWhereClause(filterParam, paramUser);
		
		// check result: where clause text
		assertEquals(result, " WHERE LOWER(e.address) = LOWER(:u.email)");
		
		// check result: parameters should be set in user object 
		assertEquals(email, paramUser.getEmail());
		
		// verify mock
		verify(testee, atLeastOnce()).createQueryHelper();
		verify(testee).populate(paramUser, filterParam.getParamMap());
	}
	
	@Test
	public void testBuildWhereClause_WithConditionOfStatus() throws Exception {
		// active
		testBuildWhereClause_WithConditionOfStatus(true);
		// inactive
		testBuildWhereClause_WithConditionOfStatus(false);
	}

	protected void testBuildWhereClause_WithConditionOfStatus(boolean active) throws Exception {
		// parameters
		User paramUser = new User();
		FilterParameter filterParam = new FilterParameter(null);
		filterParam.put("active", active);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createQueryHelper();
		doCallRealMethod().when(testee).populate(paramUser, filterParam.getParamMap());
		doCallRealMethod().when(testee).buildWhereClause(filterParam, paramUser);

		// test
		String result = testee.buildWhereClause(filterParam, paramUser);
		
		// check result: where clause text
		assertEquals(" WHERE u.status = " + (active ? "'A'" : "'U'"), result);
		
		// verify mock
		verify(testee, atLeastOnce()).createQueryHelper();
		verify(testee).populate(paramUser, filterParam.getParamMap());
	}

	@Test
	public void testBuildOffsetClause() throws Exception {
		// parameters
		int iLimit = 100, iOffset = 200;
		LimitQuery limit = new LimitQuery(iLimit, iOffset);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).buildOffsetClause(any(LimitQuery.class));

		// test
		String result = testee.buildOffsetClause(limit);
		
		// verify result
		assertEquals(String.format("SKIP %d", iOffset), result);
	}

	@Test
	public void testBuildOffsetClause_IAE_WhenOffsetIsNegative() throws Exception {
		// parameters
		int iLimit = 100, iOffset = -1;
		LimitQuery limit = new LimitQuery(iLimit, iOffset);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).buildOffsetClause(any(LimitQuery.class));

		// test
		try {
			testee.buildOffsetClause(limit);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
		
		// test2: buildOffsetClause() returns null if offset is 0
		limit.setOffset(0);
		String result = testee.buildOffsetClause(limit);
		
		assertNull(result);
	}
	
	/*
	protected String buildJoinOnEmail(FilterParameter filterParam) {
		return (filterParam!=null && filterParam.getParamMap() !=null && filterParam.getParamMap().containsKey("email")) ?
				"INNER JOIN" : "LEFT OUTER JOIN";
	}
	 */
	@Test
	public void testBuildJoinOnEmail_Returns_INNER_JOIN_WhenConditionIsSpecifiedOnEmail() throws Exception {
		
		// parameters
		FilterParameter filterParam = new FilterParameter(null);
		filterParam.put("email", "jdoe@appirio.com");
		assertTrue(filterParam.getParamMap().containsKey("email"));

		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).buildJoinOnEmail(any(FilterParameter.class));

		// test
		String result = testee.buildJoinOnEmail(filterParam);
		assertEquals("INNER JOIN", result);
	}
	
	@Test
	public void testBuildJoinOnEmail_Returns_LEFT_OUTER_JOIN_WhenNothingIsSpecifiedOnEmail() throws Exception {
		
		// parameters
		FilterParameter filterParam = new FilterParameter(null);
		filterParam.put("handle", "jdoe");
		assertFalse(filterParam.getParamMap().containsKey("email"));

		//testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).buildJoinOnEmail(any(FilterParameter.class));

		// test
		String result1 = testee.buildJoinOnEmail(filterParam);
		assertEquals("LEFT OUTER JOIN", result1);
		
		String result2 = testee.buildJoinOnEmail(null);
		assertEquals("LEFT OUTER JOIN", result2);
	}


	/**
     * Test populate by i with default fields
     *
     * @throws Exception if any error occurs
     */
	@Test
	public void testPopulateById_WithDefaultFields() throws Exception {
		// data
		long userId = 123456L;
		User user = createTestUser(userId);
		
		List<UserProfile> ssoProfiles = new ArrayList<UserProfile>();
        
		// testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.populateById(any(FieldSelector.class), any(TCID.class))).thenCallRealMethod();
		when(testee.hasField(any(FieldSelector.class), anyString())).thenCallRealMethod();
		// mock
		when(testee.findUserById(userId)).thenReturn(user);
		
		SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(ssoUserDao.findProfilesByUserId(userId)).thenReturn(ssoProfiles);
        when(testee.findUserById(userId)).thenReturn(user);
        when(testee.createSSOUserDAO()).thenReturn(ssoUserDao);
		
		// default fileds
		FieldSelector defaultFieldsSelector = ResourceHelper.getDefaultFieldSelector(User.class);
		assertNull("profiles should not be included in default api fields.", defaultFieldsSelector.getField("profiles"));
		
		// test
		TCID id = new TCID(userId);
		User result = testee.populateById(defaultFieldsSelector, id);
		
		// verify
		assertEquals(user, result);
		
		verify(testee).findUserById(userId);
		verify(testee).hasField(defaultFieldsSelector, "profiles");
		verify(testee, never()).createSocialUserDAO();
	}
	
	/**
     * Test populate by id  with profiles
     *
     * @throws Exception if any error occurs
     */
	@Test
	public void testPopulateById_WithProfiles() throws Exception {
		// data
		long userId = 123456L;
		User user = createTestUser(userId);
		
		List<UserProfile> ssoProfiles = new ArrayList<UserProfile>();
		List<UserProfile> socialProfiles = new ArrayList<UserProfile>();
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.populateById(any(FieldSelector.class), any(TCID.class))).thenCallRealMethod();
		when(testee.hasField(any(FieldSelector.class), anyString())).thenCallRealMethod();

		// mock
		SocialUserDAO socialUserDao = mock(SocialUserDAO.class);
		when(socialUserDao.findProfilesByUserId(userId)).thenReturn(socialProfiles);
		when(testee.findUserById(userId)).thenReturn(user);
		when(testee.createSocialUserDAO()).thenReturn(socialUserDao);
		
		SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(ssoUserDao.findProfilesByUserId(userId)).thenReturn(ssoProfiles);
        when(testee.findUserById(userId)).thenReturn(user);
        when(testee.createSSOUserDAO()).thenReturn(ssoUserDao);
		
		// default fileds
		FieldSelector selector = FieldSelector.instanceFromV2String("id,handle,profiles");
		assertNotNull("profiles should be included in FieldSelector", selector.getField("profiles"));
		
		// test
		TCID id = new TCID(userId);
		User result = testee.populateById(selector, id);
		
		// verify
		assertEquals(user, result);
		assertEquals(socialProfiles, result.getProfiles());
		
		verify(testee).findUserById(userId);
		verify(testee).hasField(selector, "profiles");
		verify(testee).createSocialUserDAO();
		verify(socialUserDao).findProfilesByUserId(userId);
	}
	
	/**
     * Test populate by id  with profiles_sso login
     *
     * @throws Exception if any error occurs
     */
	@Test
    public void testPopulateById_WithProfiles_SSOLogin() throws Exception {
        // data
        long userId = 123456L;
        User user = createTestUser(userId);
        
        List<UserProfile> ssoProfiles = new ArrayList<UserProfile>();
        ssoProfiles.add(new UserProfile());
        
        List<UserProfile> socialProfiles = new ArrayList<UserProfile>();
        
        // testee
        UserDAO testee = mock(UserDAO.class);
        when(testee.populateById(any(FieldSelector.class), any(TCID.class))).thenCallRealMethod();
        when(testee.hasField(any(FieldSelector.class), anyString())).thenCallRealMethod();

        // mock
        SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
        when(ssoUserDao.findProfilesByUserId(userId)).thenReturn(ssoProfiles);
        when(testee.findUserById(userId)).thenReturn(user);
        when(testee.createSSOUserDAO()).thenReturn(ssoUserDao);
        
        SocialUserDAO socialUserDao = mock(SocialUserDAO.class);
        when(socialUserDao.findProfilesByUserId(userId)).thenReturn(socialProfiles);
        when(testee.findUserById(userId)).thenReturn(user);
        when(testee.createSocialUserDAO()).thenReturn(socialUserDao);
        
        // default fileds
        FieldSelector selector = FieldSelector.instanceFromV2String("id,handle,profiles");
        assertNotNull("profiles should be included in FieldSelector", selector.getField("profiles"));
        
        // test
        TCID id = new TCID(userId);
        User result = testee.populateById(selector, id);
        
        // verify
        assertEquals(user, result);
        assertEquals(ssoProfiles, result.getProfiles());
        
        verify(testee).findUserById(userId);
        verify(testee).hasField(selector, "profiles");
        verify(testee).createSSOUserDAO();
        verify(ssoUserDao).findProfilesByUserId(userId);
    }
	
	
	@Test
	public void testHandleExists() throws Exception {
		
		UserDAO testee = mock(UserDAO.class);
		
		final String handle = "jdoe";
		when(testee.handleExists(anyString())).thenCallRealMethod(); // testee
		when(testee.findUserByHandle(handle)).thenReturn(new User());
		
		// handle of existing user
		boolean result = testee.handleExists(handle);
		assertTrue("handleExists(existing-handle) should return true", result);
		verify(testee).findUserByHandle(handle);
		
		// unregistered handle
		when(testee.findUserByHandle(handle)).thenReturn(null);
		result = testee.handleExists(handle);
		assertFalse("handleExists(unregistered-handle) should return false", result);
		
		// null
		when(testee.findUserByHandle(null)).thenReturn(null); // Not sure
		result = testee.handleExists(null);
		assertFalse("handleExists(null) should return false", result);
		
		// exception
		RuntimeException error = new RuntimeException();
		when(testee.findUserByHandle(handle)).thenThrow(error); // unexpected error
		try {
			result = testee.handleExists(handle);
			fail("handleExists(handle) should throw an exception.");
		} catch (Exception e) {
			assertEquals(error, e);
		}
	}
	
	@Test
	public void testEmailExists() throws Exception {
		
		String newEmail = "new@appirio.com";
		
		// mock
		EmailDAO emailDao = mock(EmailDAO.class);
		doReturn(false).when(emailDao).emailExists(newEmail);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).emailExists(anyString());
		doReturn(emailDao).when(testee).createEmailDAO();
		
		// test
		boolean result = testee.emailExists(newEmail);
		assertFalse(result);
		
		verify(emailDao).emailExists(newEmail);
		verify(testee).createEmailDAO();
	}
	
	@Test
	public void testSocialUserExists() throws Exception {
		
		// data
		String socialId = "jdoe";
		UserProfile socialProfile = new UserProfile();
		socialProfile.setUserId(socialId);
		socialProfile.setProviderType(ProviderType.FACEBOOK.name);
		
		// mock
		SocialUserDAO socialUserDao = mock(SocialUserDAO.class);
		when(socialUserDao.socialIdExists(socialId, ProviderType.FACEBOOK)).thenReturn(true); // exists
		when(socialUserDao.socialIdExists(socialId, ProviderType.GITHUB)).thenReturn(false); // not exists
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.createSocialUserDAO()).thenReturn(socialUserDao);
		when(testee.socialUserExists(any(UserProfile.class))).thenCallRealMethod();
		
		// test - used account
		boolean result = testee.socialUserExists(socialProfile);
		
		assertTrue("socialUserExists() should return true for account which is already in use.", result);
		verify(socialUserDao).socialIdExists(socialId, ProviderType.FACEBOOK);

		// data - unused account
		UserProfile socialProfileUnused = new UserProfile();
		socialProfileUnused.setUserId(socialId);
		socialProfileUnused.setProviderType(ProviderType.GITHUB.name);

		// test
		result = testee.socialUserExists(socialProfileUnused);
		assertFalse("socialUserExists() should return false for unused account.", result);
		verify(socialUserDao).socialIdExists(socialId, ProviderType.GITHUB);
	}
	
	@Test
	public void testSsoUserExists_TrueWhenUserExists() throws Exception {
		testSsoUserExists(true);
	}
	
	@Test
	public void testSsoUserExists_FalseWhenUserDoesNotExist() throws Exception {
		testSsoUserExists(false);
	}
	
	public void testSsoUserExists(boolean userExists) throws Exception {
		// data
		String ssoUserId = "jdoe";
		UserProfile ssoProfile = new UserProfile();
		ssoProfile.setUserId(ssoUserId);
		ssoProfile.setProviderType(ProviderType.SAMLP.name);
		ssoProfile.setProvider("SSO-PROVIDER");
		
		// mock
		Long userId = userExists ? 123456L : null; // user-id for an existing user (null for the case that user does not exist)
		SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
		when(ssoUserDao.findUserIdByProfile(ssoProfile)).thenReturn(userId);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.createSSOUserDAO()).thenReturn(ssoUserDao);
		when(testee.ssoUserExists(any(UserProfile.class))).thenCallRealMethod();

		// test
		boolean result = testee.ssoUserExists(ssoProfile);
		
		// verify
		assertEquals(userExists, result);

		verify(testee).createSSOUserDAO();
		verify(ssoUserDao).findUserIdByProfile(ssoProfile);
	}
		
	@Test
	public void testIsInvalidHandle_InvalidHandleDetectedByIsExactInvalidHandle() throws Exception {
		
		UserDAO testee = mock(UserDAO.class);
		
		final String handle = "ngword";
		when(testee.isInvalidHandle(anyString())).thenCallRealMethod(); // testee
		when(testee.isExactInvalidHandle(handle)).thenReturn(true); // handle is invalid
		
		// test
		boolean result = testee.isInvalidHandle(handle);
		
		// verify
		assertTrue("isInvalidHandle() should return true when the handle is invalid.", result);
		verify(testee).isExactInvalidHandle(handle);
	}
	
	@Test
	public void testIsInvalidHandle_InvalidHandleDetectedByIsHandleContainingNGWordWithNumberTrimmingTokenExtractor() throws Exception {
		
		UserDAO testee = mock(UserDAO.class);
		
		final String handle = "ngword01";
		when(testee.isInvalidHandle(anyString())).thenCallRealMethod(); // testee
		when(testee.isExactInvalidHandle(handle)).thenReturn(false); // isExactInvalidHandle() tells it's valid
		when(testee.isHandleContainingNGWord(eq(handle), any(NumberTrimmingTokenExtractor.class))).thenReturn(true); // invalid
		// test
		boolean result = testee.isInvalidHandle(handle);
		
		// verify
		assertTrue("isInvalidHandle() should return true when the handle is invalid.", result);
		verify(testee).isExactInvalidHandle(handle);
		verify(testee).isHandleContainingNGWord(eq(handle), any(NumberTrimmingTokenExtractor.class));
	}
	
	@Test
	public void testIsInvalidHandle_InvalidHandleDetectedByIsHandleContainingNGWordWithRegexTokenExtractor() throws Exception {
		
		UserDAO testee = mock(UserDAO.class);
		
		final String handle = "_ngwords";
		when(testee.isInvalidHandle(anyString())).thenCallRealMethod(); // testee
		when(testee.isExactInvalidHandle(handle)).thenReturn(false); // isExactInvalidHandle() tells it's valid
		when(testee.isHandleContainingNGWord(eq(handle), any(NumberTrimmingTokenExtractor.class))).thenReturn(false); // also tells it's valid
		when(testee.isHandleContainingNGWord(eq(handle), any(RegexTokenExtractor.class))).thenReturn(true); // invalid
		// test
		boolean result = testee.isInvalidHandle(handle);
		
		// verify
		assertTrue("isInvalidHandle() should return true when the handle is invalid.", result);
		verify(testee).isExactInvalidHandle(handle);
		verify(testee).isHandleContainingNGWord(eq(handle), any(NumberTrimmingTokenExtractor.class));
		verify(testee).isHandleContainingNGWord(eq(handle), any(RegexTokenExtractor.class));
	}
	
	@Test
	public void testIsInvalidHandle_HandleIsValid() throws Exception {
		
		UserDAO testee = mock(UserDAO.class);
		
		final String handle = "jdoe";
		when(testee.isInvalidHandle(anyString())).thenCallRealMethod(); // testee
		// the handle is valid when passing the following 3 validations. 
		when(testee.isExactInvalidHandle(handle)).thenReturn(false); // valid
		when(testee.isHandleContainingNGWord(eq(handle), any(NumberTrimmingTokenExtractor.class))).thenReturn(false); // valid
		when(testee.isHandleContainingNGWord(eq(handle), any(RegexTokenExtractor.class))).thenReturn(false); // valid
		// test
		boolean result = testee.isInvalidHandle(handle);
		
		// verify
		assertFalse("isInvalidHandle() should return false when the handle is valid.", result);
		verify(testee).isExactInvalidHandle(handle);
		verify(testee, times(2)).isHandleContainingNGWord(eq(handle), any(TokenExtractor.class));
	}

	@Test
	public void testIsExactInvalidHandle() throws Exception {
		// testee
		final String handle = "ngword";
		UserDAO testee = mock(UserDAO.class);
		when(testee.isExactInvalidHandle(anyString())).thenCallRealMethod();
		// mock
		when(testee.checkInvalidHandle(handle)).thenReturn(0); // 0 means the handle is not registered in the black list.

		// test
		boolean result = testee.isExactInvalidHandle(handle);
		
		// verify
		assertFalse("isExactInvalidHandle(handle) should return false when the handle is valid.", result);
		verify(testee).checkInvalidHandle(handle);
	}
	
	@Test
	public void testIsExactInvalidHandle_HandleIsFoundInBlackList() throws Exception {
		// testee
		final String handle = "ngword";
		UserDAO testee = mock(UserDAO.class);
		when(testee.isExactInvalidHandle(anyString())).thenCallRealMethod();
		// mock
		when(testee.checkInvalidHandle(handle)).thenReturn(1); // 1 means the handle is registered in the black list.

		// test
		boolean result = testee.isExactInvalidHandle(handle);
		
		// verify
		assertTrue("isExactInvalidHandle(handle) should return true when the handle is not valid.", result);
		verify(testee).checkInvalidHandle(handle);
	}
	
	@Test
	public void testIsHandleContainingNGWord_HandleContainsNoNGWord() throws Exception {
		// testee
		final String handle = "jdoe";
		UserDAO testee = mock(UserDAO.class);
		when(testee.isHandleContainingNGWord(anyString(), any(TokenExtractor.class))).thenCallRealMethod();

		// mock
		when(testee.isExactInvalidHandle(anyString())).thenReturn(true); // this won't be used in this test.
		TokenExtractor tokenExtractor = mock(TokenExtractor.class);
		when(tokenExtractor.extractTokens(handle)).thenReturn(new HashSet<String>());
		
		// test
		boolean result = testee.isHandleContainingNGWord(handle, tokenExtractor);
		
		// verify
		assertFalse("isHandleContainingNGWord() should return false when the TokenExtractor does not return any token for validation.", result);
		
		verify(testee, never()).isExactInvalidHandle(handle);
		verify(tokenExtractor).extractTokens(handle);
	}
	
	@Test
	public void testIsHandleContainingNGWord_HandleContainsTokenWhichIsValid() throws Exception {
		// testee
		final String handle = "dummy";
		UserDAO testee = mock(UserDAO.class);
		when(testee.isHandleContainingNGWord(anyString(), any(TokenExtractor.class))).thenCallRealMethod();

		// mock
		String token = "valid";
		Set<String> candidateTokens = new HashSet<String>(Arrays.asList(token));
		TokenExtractor tokenExtractor = mock(TokenExtractor.class);
		when(tokenExtractor.extractTokens(handle)).thenReturn(candidateTokens);
		when(testee.isExactInvalidHandle(token)).thenReturn(false); // valid
		
		// test
		boolean result = testee.isHandleContainingNGWord(handle, tokenExtractor);
		
		// verify
		assertFalse("isHandleContainingNGWord() should return false when the handle is valid.", result);
		
		verify(tokenExtractor).extractTokens(handle);
		verify(testee).isExactInvalidHandle(token);
	}
	
	@Test
	public void testIsHandleContainingNGWord_HandleContainsTokenWhichIsInvalid() throws Exception {
		// testee
		final String handle = "dummy";
		UserDAO testee = mock(UserDAO.class);
		when(testee.isHandleContainingNGWord(anyString(), any(TokenExtractor.class))).thenCallRealMethod();

		// mock
		String token1 = "valid";
		String token2 = "ngword";
		Set<String> candidateTokens = new HashSet<String>(Arrays.asList(token1, token2));
		TokenExtractor tokenExtractor = mock(TokenExtractor.class);
		when(tokenExtractor.extractTokens(handle)).thenReturn(candidateTokens);
		when(testee.isExactInvalidHandle(token1)).thenReturn(false); // valid
		when(testee.isExactInvalidHandle(token2)).thenReturn(true);  // invalid
		
		// test
		boolean result = testee.isHandleContainingNGWord(handle, tokenExtractor);
		
		// verify
		assertTrue("isHandleContainingNGWord() should return true when the handle contains invalid token.", result);
		
		verify(tokenExtractor).extractTokens(handle);
		verify(testee).isExactInvalidHandle(token1);
		verify(testee).isExactInvalidHandle(token2);
	}
	
	@Test
	public void testRegister() {
		User user = new User();
		testRegisterWith(user);
	}
	
	@Test
	public void testRegister_WithActiveUser() {
		User user = new User();
		user.setActive(true);
		testRegisterWith(user);
	}
	
	@Test
	public void testRegister_WithReferralProgramCampaign() {
		User user = new User();
		user.setUtmCampaign("ReferralProgram");
		user.setUtmSource("handle");
		testRegisterWith(user);
	}
	
	public void testRegisterWith(User user) {
		
		UserDAO testee = mock(UserDAO.class);
		when(testee.register(any(User.class))).thenCallRealMethod(); // testee
		
		// mock::sequenceDAO
		long newUserId = 101L;
		long newEmailId = 201L;
		when(testee.nextSequeceValue("sequence_user_seq")).thenReturn(newUserId);
		when(testee.nextSequeceValue("sequence_email_seq")).thenReturn(newEmailId);
		
		// test data
		if(user==null)
			user = new User();
		if(user.getHandle()==null)
			user.setHandle("jdoe");
		if(user.getEmail()==null)
			user.setEmail("jdoe@examples.com");
		if(user.getCredential()==null) {
			user.setCredential(new Credential());
		}
		if(user.getCredential().getPassword()==null) {
			user.getCredential().setPassword("passpass");
		}
		
		// test
		TCID result = testee.register(user);
		
		// verify
		assertNotNull("register(user) should not return null", result);
		assertEquals(result.getId(), String.valueOf(newUserId));

		// activation code should be issued for non-active user.
		if(!user.isActive()) {
			assertEquals(Utils.getActivationCode(newUserId),
							user.getCredential().getActivationCode());
		} else {
			assertNull(user.getCredential().getActivationCode());
		}
		
		verify(testee).createUser(eq(user), any());
		verify(testee).createSecurityUser(newUserId, user.getHandle(), user.getCredential().getEncodedPassword());
		int emailStatus = user.isActive() ? Constants.EMAIL_STATUS_ID_ACTIVE : Constants.EMAIL_STATUS_ID_INACTIVE;
		verify(testee).registerEmail(newUserId, newEmailId, user.getEmail(), emailStatus);
		verify(testee).createCoder(eq(user));
		
		// createReferral should be called only when utmCampaign == "ReferralProgram".
		if("ReferralProgram".equals(user.getUtmCampaign())) {
			verify(testee).createReferral(eq(user));			
		} else {
			verify(testee, never()).createReferral(any(User.class));
		}
		verify(testee).cretateAlgoRating(newUserId);
		verify(testee).addUserToDefaultGroups(user);
		verify(testee).registerLDAP(user);
	}
	
	@Test
	public void testRegister_IAEWhenUserIsNull() {
		UserDAO testee = mock(UserDAO.class);
		when(testee.register(any(User.class))).thenCallRealMethod(); // testee

		// test
		try {
			testee.register(null);
			fail("register(null) should throw IllegalArgumentException.");
		} catch (IllegalArgumentException e) {
		}
	}
	
	@Test
	public void testRegister_WithLDAPProfile() throws Exception {
		
		// test data - profile
		UserProfile profile = new UserProfile();
		profile.setProviderType(ProviderType.LDAP.name);
		
		// test
		testRegister_WithProfile(profile);
	}

	
	@Test
	public void testRegister_WithSocialProfile() throws Exception {
		
		// test data - profile
		UserProfile profile = new UserProfile();
		profile.setProviderType(ProviderType.FACEBOOK.name);
		profile.setUserId("SOCIAL-USER-ID");
		profile.setEmail("SOCIAL-EMAIL");
		
		// test
		testRegister_WithProfile(profile);
	}
	
	@Test
	public void testRegister_WithSSOProfile() throws Exception {
		
		// test data - profile
		UserProfile profile = new UserProfile();
		profile.setProviderType(ProviderType.SAMLP.name);
		profile.setProvider("SAMLP-PROVIDER");
		profile.setUserId("SSO-USER-ID");
		profile.setEmail("SSO-EMAIL");
		
		// test
		testRegister_WithProfile(profile);
	}

	
	@SuppressWarnings("serial")
	public void testRegister_WithProfile(UserProfile profile) throws Exception {
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.register(any(User.class))).thenCallRealMethod();
		
		// mock
		long newUserId = 101L;
		long newEmailId = 201L;
		when(testee.nextSequeceValue("sequence_user_seq")).thenReturn(newUserId);
		when(testee.nextSequeceValue("sequence_email_seq")).thenReturn(newEmailId);
		
		SocialUserDAO socialUserDao = mock(SocialUserDAO.class);
		when(testee.createSocialUserDAO()).thenReturn(socialUserDao);
		SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
		when(testee.createSSOUserDAO()).thenReturn(ssoUserDao);
		
		// test data - user
		User user = new User();
		user.setHandle("jdoe");
		user.setEmail("jdoe@examples.com");
		user.setCredential(new Credential());
		user.getCredential().setPassword("passpass");
		user.setProfiles(new ArrayList<UserProfile>(){{ add(profile); }});
		
		// test
		TCID result = testee.register(user);
		
		// verify
		assertNotNull("register(user) should not return null", result);
		assertEquals(result.getId(), String.valueOf(newUserId));
		
		verify(testee).createUser(eq(user), anyString());
		verify(testee).createSecurityUser(newUserId, user.getHandle(), user.getCredential().getEncodedPassword());
		verify(testee).registerEmail(newUserId, newEmailId, user.getEmail(), Constants.EMAIL_STATUS_ID_INACTIVE);
		verify(testee).createCoder(eq(user));
		verify(testee).addUserToDefaultGroups(user);
		verify(testee).registerLDAP(user);
		
		if(profile.isSocial()) {
			verify(testee).createSocialUser(newUserId, profile);
			//verify(socialUserDao).createSocialUser(Utils.toLongValue(user.getId()), profile);
			verify(ssoUserDao, never()).createSSOUser(anyLong(), any(UserProfile.class));
		}
		if(profile.isEnterprise()) {
			// LDAP is the internal IdP. No SSO setting created for LDAP profile
			if(profile.getProviderTypeEnum() == ProviderType.LDAP) {
				verify(ssoUserDao, never()).createSSOUser(anyLong(), any(UserProfile.class));
				verify(socialUserDao, never()).createSocialUser(anyLong(), any(UserProfile.class));
			} else {
				// case of external IdPs
				verify(ssoUserDao).createSSOUser(Utils.toLongValue(user.getId()), profile);
				verify(socialUserDao, never()).createSocialUser(anyLong(), any(UserProfile.class));
			}
		}
	}
	
	@Test
	public void testRegisterEmail() throws Exception {
		// data
		long userId = 123456L;
		long emailId = 234567L;
		String email = "jdoe@appirio.com";
		int statusId = 1;
		
		// mock
		EmailDAO emailDao = mock(EmailDAO.class);
		int emailDaoResult = 1;
		doReturn(emailDaoResult).when(emailDao).createEmail(userId, emailId, email, statusId);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).registerEmail(anyLong(), anyLong(), anyString(), anyInt());
		doReturn(emailDao).when(testee).createEmailDAO();

		// test
		int result = testee.registerEmail(userId, emailId, email, statusId);
		assertEquals(emailDaoResult, result);
		
		verify(emailDao).createEmail(userId, emailId, email, statusId);
		verify(testee).createEmailDAO();
	}
	
	@Test
	public void testCreateCoder() throws Exception {
		
		// data
		Long userId = 123456L;
		User user = createTestUser(userId);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createCoder(any(User.class));

		// mock
		String cuntryCode = "999";
		doReturn(cuntryCode).when(testee).getCode(user.getCountry());
		
		// test
		testee.createCoder(user);
		
		// verify
		verify(testee).getCode(user.getCountry());
		verify(testee).createCoder(userId, cuntryCode);
	}
	
	@Test
	public void testCreateCoder_WithoutCountry() throws Exception {
		// data
		Long userId = 123456L;
		User user = createTestUser(userId);
		user.setCountry(null); // no country
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createCoder(any(User.class));

		// test
		testee.createCoder(user);
		
		// verify
		verify(testee, never()).getCode(user.getCountry());
		verify(testee).createCoder(userId, null); // null to country code
	}
	
	@Test
	public void testCreateReferral()  throws Exception {
		// data
		Long userId = 123456L;
		User user = createTestUser(userId);
		user.setUtmCampaign("ReferralProgram");
		user.setUtmSource("Handle");
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createReferral(user);
		
		// test
		testee.createReferral(user);
		
		// verify
		verify(testee).createReferral(userId, user.getUtmSource());
	}
	
	@Test
	public void testCreateReferral_ErrWhenUtmSourceNotSpecified()  throws Exception {
		// data
		Long userId = 123456L;
		User user = createTestUser(userId);
		user.setUtmCampaign("ReferralProgram");
		user.setUtmSource(null); // not specified
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createReferral(user);
		
		// test
		try {
			testee.createReferral(user);
			fail("Exception should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
		
		// verify
		verify(testee, never()).createReferral(anyLong(), anyString());
	}
	
	@Test
	public void testGetCode() throws Exception {
		// data
		String countryName = "United States";
		String countryCode = "840";
		Country country = new Country(countryCode, countryName);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).getCode(any(Country.class));

		// test
		String result = testee.getCode(country);
		
		// verify
		assertEquals(countryCode, result);
	}

	@Test
	public void testGetCode_FindCodeByName() throws Exception {
		// data
		String countryName = "United States";
		Country country = new Country(null, countryName); // country has only name
		
		// testee
		String countryCode = "840";
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).getCode(any(Country.class));

		// mock
		doReturn(new Country(countryCode, countryName)).when(testee).findCountryBy(country);
		
		// test
		String result = testee.getCode(country);
		
		// verify
		assertEquals(countryCode, result);
		
		verify(testee).findCountryBy(country);
	}
	
	@Test
	public void testGetCode_NullWhenCountryIsNotFound() throws Exception {
		// data
		Country country = new Country(); // country has no value
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).getCode(any(Country.class));

		// mock
		doReturn(null).when(testee).findCountryBy(country); // not found

		// test
		String result = testee.getCode(country);
		
		// verify
		assertNull(result);
		
		verify(testee).findCountryBy(country);
	}

	@Test
	public void testFindCountryBy_NullWhenInputCounryIsNull() throws Exception {
		// testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.findCountryBy(any(Country.class))).thenCallRealMethod();
		
		// test
		Country result = testee.findCountryBy(null);
		
		// verify
		assertNull(result);
	}

	@Test
	public void testFindCountryBy_NullWhenInputCounryIsEmpty() throws Exception {
		// testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.findCountryBy(any(Country.class))).thenCallRealMethod();
		
		// test
		Country result = testee.findCountryBy(new Country());
		
		// verify
		assertNull(result);
	}

	@Test
	public void testFindCountryBy_FoundByCountryCode() throws Exception {
		// data
		Country country = new Country();
		country.setCode("123");
		
		// testee
		UserDAO userDao = createMockUserDAOForCountry(country);
		when(userDao.findCountryBy(any(Country.class))).thenCallRealMethod();
		
		// test
		Country result = userDao.findCountryBy(country);
		
		// verify
		assertEquals(result, country);
		verify(userDao).findCountryByCode(country.getCode());
		verify(userDao, never()).findCountryByISOAlpha2Code(anyString());
		verify(userDao, never()).findCountryByISOAlpha3Code(anyString());
	}
	
	@Test
	public void testFindCountryBy_FoundByISOAlpha2Code() throws Exception {
		// data
		Country country = new Country();
		country.setISOAlpha2Code("DM");
		
		// testee
		UserDAO userDao = createMockUserDAOForCountry(country);
		when(userDao.findCountryBy(any(Country.class))).thenCallRealMethod();
		
		// test
		Country result = userDao.findCountryBy(country);
		
		// verify
		assertEquals(result, country);
		verify(userDao, never()).findCountryByCode(anyString());
		verify(userDao).findCountryByISOAlpha2Code(country.getISOAlpha2Code());
		verify(userDao, never()).findCountryByISOAlpha3Code(anyString());
	}
	
	@Test
	public void testFindCountryBy_FoundByISOAlpha3Code() throws Exception {
		// data
		Country country = new Country();
		country.setISOAlpha3Code("DMM");
		
		// testee
		UserDAO userDao = createMockUserDAOForCountry(country);
		when(userDao.findCountryBy(any(Country.class))).thenCallRealMethod();
		
		// test
		Country result = userDao.findCountryBy(country);
		
		// verify
		assertEquals(result, country);
		verify(userDao, never()).findCountryByCode(anyString());
		verify(userDao, never()).findCountryByISOAlpha2Code(anyString());
		verify(userDao).findCountryByISOAlpha3Code(country.getISOAlpha3Code());
	}
	
	@Test
	public void testFindCountryBy_FoundByCountryName() throws Exception {
		// data
		Country country = new Country();
		country.setName("DUMMY-COUNTRY");
		
		// testee
		UserDAO userDao = createMockUserDAOForCountry(country);
		when(userDao.findCountryBy(any(Country.class))).thenCallRealMethod();
		
		// test
		Country result = userDao.findCountryBy(country);
		
		// verify
		assertEquals(result, country);
		verify(userDao, never()).findCountryByCode(anyString());
		verify(userDao, never()).findCountryByISOAlpha2Code(anyString());
		verify(userDao, never()).findCountryByISOAlpha3Code(anyString());
		verify(userDao).findCountryByName(country.getName());
	}
	
	@Test
	public void testFindCountryBy_NotFoundAnyCountry() throws Exception {

		// data
		Country country = new Country();
		country.setCode("999");
		country.setISOAlpha2Code("AA");
		country.setISOAlpha3Code("AAA");
		country.setName("DUMMY-COUNTRY");

		// data
		Country countryInDb = new Country();
		countryInDb.setCode("123");
		countryInDb.setISOAlpha2Code("DM");
		countryInDb.setISOAlpha3Code("DMM");
		countryInDb.setName("ANOTHER-COUNTRY");
		
		// testee
		UserDAO userDao = createMockUserDAOForCountry(countryInDb);
		when(userDao.findCountryBy(any(Country.class))).thenCallRealMethod();
		
		// test
		Country result = userDao.findCountryBy(country);
		
		// verify
		assertNull(result);
		verify(userDao).findCountryByCode(country.getCode());
		verify(userDao).findCountryByISOAlpha2Code(country.getISOAlpha2Code());
		verify(userDao).findCountryByISOAlpha3Code(country.getISOAlpha3Code());
		verify(userDao).findCountryByName(country.getName());
	}
	
	protected UserDAO createMockUserDAOForCountry(Country countryInDb) {
		if(countryInDb==null) {
			countryInDb = new Country();
			countryInDb.setCode("123");
			countryInDb.setName("DUMMY-COUNTRY");
			countryInDb.setISOAlpha2Code("DM");
			countryInDb.setISOAlpha3Code("DMM");
		}
		// mock
		UserDAO userDao = mock(UserDAO.class);
		doReturn(countryInDb).when(userDao).findCountryByCode(countryInDb.getCode());
		doReturn(countryInDb).when(userDao).findCountryByISOAlpha2Code(countryInDb.getISOAlpha2Code());
		doReturn(countryInDb).when(userDao).findCountryByISOAlpha3Code(countryInDb.getISOAlpha3Code());
		doReturn(countryInDb).when(userDao).findCountryByName(countryInDb.getName());
		return userDao; 
	}
	
	protected UserDAO createMockUserDAOForCountryTest() {
		return createMockUserDAOForCountry(null);
	}
	
	@Test
	public void testAddUserToDefaultGroups() throws Exception {

		// test data
		long userId = 123456L;
		User user = createTestUser(userId);
		
		// mock
		SequenceDAO sequenceDao = mock(SequenceDAO.class);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doReturn(sequenceDao).when(testee).createSequenceDAO();
		doCallRealMethod().when(testee).addUserToDefaultGroups(any(User.class));
		
		// test
		testee.addUserToDefaultGroups(user);

		// verify
		verify(testee).createSequenceDAO();
		// user should be added to all default groups 
		for(int i=0; i<UserDAO.DEFAULT_GROUPS.length; i++) {
			verify(testee).addUserToGroup(eq(sequenceDao), eq(user), eq(UserDAO.DEFAULT_GROUPS[0]));
		}
	}
	
	@Test
	public void testAddUserToGroup() throws Exception {
		// test data
		long userId = 123456L;
		User user = createTestUser(userId);
		long groupId = 234567L;
		long userGroupId = 345678L;
		
		// mock
		String seqName = "sequence_user_group_seq";
		SequenceDAO sequenceDao = mock(SequenceDAO.class);
		doReturn(userGroupId).when(sequenceDao).nextVal(seqName);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doReturn(sequenceDao).when(testee).createSequenceDAO();
		doCallRealMethod().when(testee).addUserToGroup(any(SequenceDAO.class), any(User.class), anyLong());

		// test
		testee.addUserToGroup(sequenceDao, user, groupId);
		
		// verify
		// - userGroupId should be issued by sequenceDao 
		verify(sequenceDao).nextVal("sequence_user_group_seq");
		// - cretateUserGroupReference() should be invoked to link user and group with userGroupId
		verify(testee).cretateUserGroupReference(eq(userGroupId), eq(userId), eq(groupId));
	}
	
	@Test
	public void testUpdate() throws Exception {
		// data
		long userId = 123456L;
		User user = createTestUser(userId);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).update(any(User.class));

		// test
		TCID result = testee.update(user);
		
		// verify
		assertEquals(userId, Utils.toLongValue(result).longValue());
		verify(testee).updateUser(user);
	}
	
	@Test
	public void testUpdate_IAE_WhenUserIsNull_OR_UserHasNoID() throws Exception {
		// data
		long userId = 123456L;
		User user = createTestUser(userId);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).update(any(User.class));

		// test
		try {
			testee.update(null);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {}
		
		user.getId().setId(null);
		try {
			testee.update(user);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {}

		user.setId(null);
		try {
			testee.update(user);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {}

		// verify
		verify(testee, never()).updateUser(user);
	}
	
	@Test
	public void testAddSocialProfile() throws Exception {
		// data
		long userId = 123456L;
		UserProfile profile = new UserProfile();
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).addSocialProfile(userId, profile);

		// test
		testee.addSocialProfile(userId, profile);
		
		// verify
		verify(testee).createSocialUser(userId, profile);
	}
	
	@Test
	public void testCreateSocialUser() throws Exception {
		// data
		long userId = 123456L;
		String socialId = "DUMMY-SOCIAL-ID";
		UserProfile profile = new UserProfile();
		profile.setUserId(socialId);
		profile.setProviderType(ProviderType.GITHUB.name);
		profile.setContext(new HashMap<String, String>());
		profile.getContext().put("p1", "v1");

		ExternalAccount externalAccount = new ExternalAccount();
		externalAccount.setAccountType(profile.getProviderType());
		externalAccount.setUserId(String.valueOf(userId));
		externalAccount.setParams(profile.getContext());
		
		// mock
		SocialUserDAO socialUserDao = mock(SocialUserDAO.class);

		// testee
		UserDAO testee = mock(UserDAO.class);
		doReturn(socialUserDao).when(testee).createSocialUserDAO();
		doReturn(externalAccount).when(testee).createExternalAccount(userId, profile.getProviderTypeEnum(), externalAccount.getParams());
		doCallRealMethod().when(testee).createSocialUser(userId, profile);
		
		// test
		testee.createSocialUser(userId, profile);

		// verify
		verify(testee).createSocialUserDAO();
		verify(testee).createExternalAccount(userId, profile.getProviderTypeEnum(), externalAccount.getParams());
		verify(testee).saveExternalAccount(externalAccount);
		
		verify(socialUserDao).createSocialUser(userId, profile);
	}
	
	@Test
	public void testCreateSocialUser_IAE_WhenProfileIsNotSocial() throws Exception {
		// data
		long userId = 123456L;
		String externalId = "DUMMY-EXTERNAL-ID";
		UserProfile profile = new UserProfile();
		profile.setUserId(externalId);
		profile.setProviderType(ProviderType.SAMLP.name); //not social

		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createSocialUser(userId, profile);
		
		// test
		try {
			testee.createSocialUser(userId, profile);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
			assertEquals("profile must be social.", e.getMessage());
		}

	}
	
	@Test
	public void testSaveExternalAccount() throws Exception {
		// data
		ExternalAccount externalAccount = new ExternalAccount();
		
		// mock
		ExternalAccountDAO externalAccountDao = mock(ExternalAccountDAO.class);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).saveExternalAccount(externalAccount);
		doCallRealMethod().when(testee).setExternalAccountDao(externalAccountDao);
		testee.setExternalAccountDao(externalAccountDao);

		// test
		testee.saveExternalAccount(externalAccount);
		
		// verify
		verify(externalAccountDao).put(externalAccount);
	}

	@Test
	public void testSaveExternalAccount_DoNothingWhenParameterIsNull() throws Exception {
		
		// mock
		ExternalAccountDAO externalAccountDao = mock(ExternalAccountDAO.class);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).saveExternalAccount(any(ExternalAccount.class));
		doCallRealMethod().when(testee).setExternalAccountDao(externalAccountDao);
		testee.setExternalAccountDao(externalAccountDao);

		// test
		testee.saveExternalAccount(null);
		
		// verify
		verify(externalAccountDao, never()).put(any(ExternalAccount.class));
	}

	@Test
	public void testCreateExternalAccount() throws Exception {
		// data
		long userId = 123456L;
		ProviderType providerType = ProviderType.GITHUB;
		Map<String, String> context = new HashMap<String, String>();

		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createExternalAccount(userId, providerType, context);
		
		// test
		ExternalAccount result = testee.createExternalAccount(userId, providerType, context);
		
		// verify
		assertNotNull(result);
		assertEquals(String.valueOf(userId), result.getUserId());
		assertEquals(providerType.name, result.getAccountType());
		assertEquals(false, result.isDeleted());
		assertEquals(false, result.hasErrored());
		assertEquals(0L, result.getSynchronizedAt());
		assertEquals(context, result.getParams());
	}
	
	@Test
	public void testCreateExternalAccount_IAE_WhenUserIdIsNotSpecified() throws Exception {
		// data
		ProviderType providerType = ProviderType.GITHUB;
		Map<String, String> context = new HashMap<String, String>();

		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createExternalAccount(any(), eq(providerType), eq(context));
		
		// test
		try {
			testee.createExternalAccount(null, providerType, context);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
			assertEquals("userId must be specified.", e.getMessage());
		}
	}
	
	@Test
	public void testCreateExternalAccount_IAE_WhenAccountTypeIsNotSpecified() throws Exception {
		// data
		long userId = 123456L;
		Map<String, String> context = new HashMap<String, String>();

		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).createExternalAccount(eq(userId), any(ProviderType.class), eq(context));
		
		// test
		try {
			testee.createExternalAccount(userId, null, context);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
			assertEquals("providerType must be specified.", e.getMessage());
		}
	}
	
	@Test
	public void testGetSocialProfiles() throws Exception {
		// data
		long userId = 123456L;
		ProviderType providerType = ProviderType.GITHUB;
		List<UserProfile> profiles = new ArrayList<UserProfile>();
		profiles.add(new UserProfile());
		
		// mock
		SocialUserDAO socialUserDao = mock(SocialUserDAO.class);
		doReturn(profiles).when(socialUserDao).findProfilesByUserIdAndProvider(userId, providerType.id); // returns test data
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doReturn(socialUserDao).when(testee).createSocialUserDAO();
		doCallRealMethod().when(testee).getSocialProfiles(userId, providerType);

		// test
		List<UserProfile> result = testee.getSocialProfiles(userId, providerType);
		
		// verify
		assertEquals(profiles, result);
		
		verify(testee).createSocialUserDAO();
		verify(socialUserDao).findProfilesByUserIdAndProvider(userId, providerType.id);
	}
	
	@Test
	public void testGetSocialProfiles_IAE_WhenSpecifiedProviderIsNotSocial() throws Exception {
		// data
		long userId = 123456L;
		ProviderType providerType = ProviderType.SAMLP; // not social
		
		// mock
		SocialUserDAO socialUserDao = mock(SocialUserDAO.class);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doReturn(socialUserDao).when(testee).createSocialUserDAO();
		doCallRealMethod().when(testee).getSocialProfiles(userId, providerType);

		// test
		try {
			testee.getSocialProfiles(userId, providerType);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
			assertEquals("providerType must be social.", e.getMessage());
		}
		
		// verify
		verify(socialUserDao, never()).findProfilesByUserIdAndProvider(anyLong(), anyInt());
	}
	
	@Test
	public void testDeleteSocialProfiles() throws Exception {
		// data
		long userId = 123456L;
		ProviderType providerType = ProviderType.GITHUB;
		
		ExternalAccount externalAccount = new ExternalAccount();
		externalAccount.setAccountType(providerType.name);
		externalAccount.setUserId(String.valueOf(userId));

		// mock
		SocialUserDAO socialUserDao = mock(SocialUserDAO.class);
		ExternalAccountDAO externalAccountDao = mock(ExternalAccountDAO.class);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).deleteSocialProfiles(userId, providerType);
		
		// mock
		doCallRealMethod().when(testee).setExternalAccountDao(externalAccountDao);
		testee.setExternalAccountDao(externalAccountDao);
		doReturn(socialUserDao).when(testee).createSocialUserDAO();
		doReturn(externalAccount).when(testee).createExternalAccount(userId, providerType, null);
		

		// test
		testee.deleteSocialProfiles(userId, providerType);
		
		// verify
		verify(testee).createSocialUserDAO();
		verify(testee).createExternalAccount(userId, providerType, null);
		verify(socialUserDao).deleteSocialUser(userId, providerType.id);
		verify(externalAccountDao).delete(externalAccount);
	}
	
	@Test
	public void testDeleteSocialProfiles_IAE_WhenSpecifiedProviderIsNotSocial() throws Exception {
		// data
		long userId = 123456L;
		ProviderType providerType = ProviderType.SAMLP; // not social
		
		ExternalAccount externalAccount = new ExternalAccount();
		externalAccount.setAccountType(providerType.name);
		externalAccount.setUserId(String.valueOf(userId));
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).deleteSocialProfiles(userId, providerType);

		// test
		try {
			testee.deleteSocialProfiles(userId, providerType);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
			assertEquals("providerType must be social.", e.getMessage());
		}
	}
	
	@Test
	public void testActivate() throws Exception {
		
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).activate(any(User.class));
		
		// test data
		long userId = 123456L;
		User user = createTestUser(userId);
		
		// test
		testee.activate(user);
		
		// verify
		assertTrue("User should be active after activation.", user.isActive());
		assertTrue("Email should be active after activation.", user.isEmailActive());
		verify(testee).activateUser(userId);
		verify(testee).activateEmail(userId);
		verify(testee).activateLDAP(userId);
	}

	@Test
	public void testActivate_IAEWhenUserIsInvalid() throws Exception {
		
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).activate(any(User.class));
		
		// test data
		long userId = 123456L;
		User user = createTestUser(userId);
		user.setId(null); // --> Wrong status
		
		// test
		try {
			testee.activate(user);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
		
		// verify
		assertFalse("User should not be active.", user.isActive());
		assertFalse("Email should not be active.", user.isEmailActive());
		verify(testee, never()).activateUser(userId);
		verify(testee, never()).activateEmail(userId);
		verify(testee, never()).activateLDAP(userId);
	}
	
	@Test
	public void testActivate_UserShouldNotBeActiveWhenErrorOccurredInActivation() throws Exception {

		// test data
		long userId = 123456L;
		User user = createTestUser(userId);

		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).activate(any(User.class));
		doThrow(RuntimeException.class).when(testee).activateLDAP(userId);
		
		// test
		try {
			testee.activate(user);
			fail("RuntimeException should be thrown in the previous step.");
		} catch (RuntimeException e) {
		}
		
		// verify
		assertFalse("User should not be active.", user.isActive());
		assertFalse("Email should not be active.", user.isEmailActive());
		verify(testee).activateUser(userId);
		verify(testee).activateEmail(userId);
		verify(testee).activateLDAP(userId);
	}
	
	@Test
	public void testUpdateHandle() throws Exception {
		// data
		long userId = 123456L;
		User user = createTestUser(userId);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updateHandle(any(User.class));
		
		// test
		testee.updateHandle(user);
		
		// verify
		verify(testee).updateHandle(userId, user.getHandle());
		verify(testee).updateSecurityUserHandle(userId, user.getHandle());
		verify(testee).updateHandleLDAP(userId, user.getHandle());
	}
	
	@Test
	public void testUpdateHandle_IAE_WhenUserIsNotSpecified() throws Exception {
		testUpdateHandle_IAE_WhenUserIsInvalid(null);
	}
	
	@Test
	public void testUpdateHandle_IAE_WhenUserHasNoHandle() throws Exception {
		// data
		long userId = 123456L;
		User user = createTestUser(userId);
		user.setHandle(null); // clear handle
		
		testUpdateHandle_IAE_WhenUserIsInvalid(user);
	}
	
	@Test
	public void testUpdateHandle_IAE_WhenUserHasInvalidUserId() throws Exception {
		// data
		long userId = 123456L;
		User user = createTestUser(userId);
		user.setId(new TCID("INVALID-ID")); // setting invalid userId
		
		testUpdateHandle_IAE_WhenUserIsInvalid(user);
	}
	
	protected void testUpdateHandle_IAE_WhenUserIsInvalid(User invalidUser) throws Exception {
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updateHandle(any(User.class));
		
		try {
			// test
			testee.updateHandle(invalidUser);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}

		// verify
		verify(testee, never()).updateHandle(anyLong(), anyString());
		verify(testee, never()).updateSecurityUserHandle(anyLong(), anyString());
		verify(testee, never()).updateHandleLDAP(anyLong(), anyString());
	}

	@Test
	public void testUpdateHandleLDAP() throws Exception {
		
		// data
		long userId = 123456L;
		String handle = "HANDLE-DUMMY";
		
		// mock
		LDAPService ldapService = mock(LDAPService.class);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updateHandleLDAP(anyLong(), anyString());
		doCallRealMethod().when(testee).setLdapService(any(LDAPService.class));
		testee.setLdapService(ldapService);
		
		// test
		testee.updateHandleLDAP(userId, handle);
		
		// verify
		verify(ldapService).changeHandleLDAPEntry(userId, handle);
	}
	
	@Test
	public void testUpdatePrimaryEmail() throws Exception {
		// data
		long userId = 123456L;
		User user = createTestUser(userId);
		assertNotNull(user.getEmail());
		
		Email email = new Email();
		email.setUserId(new TCID(userId));
		email.setAddress("OLD-EMAIL");
		assertNotEquals(email.getAddress(), user.getEmail());
		
		// mock
		EmailDAO emailDao = mock(EmailDAO.class);
		doReturn(email).when(emailDao).findPrimaryEmail(userId);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updatePrimaryEmail(any(User.class));
		doReturn(emailDao).when(testee).createEmailDAO();
		
		// test
		Email result = testee.updatePrimaryEmail(user);

		// verify results
		assertEquals(email, result);
		assertEquals(user.getEmail(), result.getAddress());
		
		verify(testee).createEmailDAO();
		verify(emailDao).findPrimaryEmail(userId);
		verify(emailDao).update(email);
	}
	
	@Test
	public void testUpdatePrimaryEmail_NothingUpdated_WhenPrimaryEmailDoesNotExist() throws Exception {
		// data
		long userId = 123456L;
		User user = createTestUser(userId);
		
		// mock
		EmailDAO emailDao = mock(EmailDAO.class);
		doReturn(null).when(emailDao).findPrimaryEmail(userId); // user does not have primary email address
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updatePrimaryEmail(any(User.class));
		doReturn(emailDao).when(testee).createEmailDAO();

		// test
		Email result = testee.updatePrimaryEmail(user);

		// verify results
		assertNull("updatePrimaryEmail(user) should return null when the user does not have primary email address", result);
		
		verify(testee).createEmailDAO();
		verify(emailDao).findPrimaryEmail(userId);
		verify(emailDao, never()).update(any(Email.class));
	}
	
	@Test
	public void testUpdatePrimaryEmail_IAE_WhenUserIsNotSpecified() throws Exception {

		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updatePrimaryEmail(any(User.class));

		try {
			testee.updatePrimaryEmail(null);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
	}

	@Test
	public void testUpdatePrimaryEmail_IAE_WhenUserHasNoEmail() throws Exception {
		// data
		long userId = 123456L;
		User user = createTestUser(userId);
		user.setEmail(null); // clear email

		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updatePrimaryEmail(any(User.class));

		try {
			testee.updatePrimaryEmail(user);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
	}

	@Test
	public void testUpdatePrimaryEmail_IAE_WhenUserHasInvalidId() throws Exception {
		// data
		long userId = 123456L;
		User user = createTestUser(userId);
		user.setId(new TCID("INVALID-ID")); // setting invalid userId

		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updatePrimaryEmail(any(User.class));

		try {
			testee.updatePrimaryEmail(user);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
	}

	@Test
	public void testUpdateStatus() throws Exception {

		// test data
		long userId = 123456L;
		User user = createTestUser(userId);
		user.setStatus(MemberStatus.INACTIVE_DUPLICATE_ACCOUNT.getValue());
		String comment = "DUMMY-COMMENT";
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updateStatus(user, comment);
		
		// test
		testee.updateStatus(user, comment);
		
		assertEquals(MemberStatus.INACTIVE_DUPLICATE_ACCOUNT.getValue(), user.getStatus());
		verify(testee).updateStatus(userId, user.getStatus());
		verify(testee).updateStatusLDAP(userId, user.getStatus());
		verify(testee).createUserAchievement(userId, comment);
	}
	
	@Test
	public void testUpdateStatus_Activate() throws Exception {

		// test data
		long userId = 123456L;
		User user = createTestUser(userId);
		user.setStatus(MemberStatus.ACTIVE.getValue());
		String comment = "DUMMY-COMMENT";
		
		assertFalse(user.isEmailActive()); // email is not active
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updateStatus(user, comment);
		
		// test
		testee.updateStatus(user, comment);
		
		assertEquals(MemberStatus.ACTIVE.getValue(), user.getStatus());
		assertTrue(user.isEmailActive());
		
		verify(testee).updateStatus(userId, user.getStatus());
		verify(testee).updateStatusLDAP(userId, user.getStatus());
		verify(testee).activateEmail(userId);
		verify(testee).createUserAchievement(userId, comment);
	}
	
	@Test
	public void testUpdateStatus_UserAchievementIsNotCreatedWhenCommentIsNull() throws Exception {

		// test data
		long userId = 123456L;
		User user = createTestUser(userId);
		user.setStatus(MemberStatus.INACTIVE_DUPLICATE_ACCOUNT.getValue());
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updateStatus(user, null);
		
		// test
		testee.updateStatus(user, null);
		
		verify(testee).updateStatus(user, null);
		verify(testee).updateStatus(userId, user.getStatus());
		verify(testee).updateStatusLDAP(userId, user.getStatus());
		verify(testee, never()).createUserAchievement(anyLong(), anyString()); // not invoked
	}
	
	@Test
	public void testUpdateStatus_IAE_WhenUserIsInvalid() throws Exception {

		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updateStatus(any(User.class), anyString());
		
		try {
			// test
			testee.updateStatus(null, "comment");
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
		
		User userWithNoId = new User();
		try {
			// test
			testee.updateStatus(userWithNoId, "comment");
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}

		User userWithInvalidId = new User();
		userWithInvalidId.setId(new TCID("TEXT-IS-NOT-ACCEPTABLE"));
		try {
			// test
			testee.updateStatus(userWithInvalidId, "comment");
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
	}
	
	@Test
	public void testAuthenticateWithHandle() throws Exception {
		
		// test data
		long userId = 123456L;
		User user = createTestUser(userId);
		String handle = user.getHandle();
		String email = user.getEmail();
		String password = user.getCredential().getPassword();
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.authenticate(anyString(), anyString())).thenCallRealMethod();
		when(testee.authenticate(any(User.class), anyString())).thenCallRealMethod();
		when(testee.findUserByHandle(handle)).thenReturn(user); // user exists in DB
		when(testee.findUserByEmail(email)).thenReturn(user);   // user exists in DB
		when(testee.authenticateLDAP(handle, password)).thenReturn(true); // user registered in LDAP

		// test
		assertFalse(handle + " is invalid for the test. This should not be an email.", Utils.isEmail(handle));
		User result = testee.authenticate(handle, password);
		
		// verify
		assertEquals(user.getHandle(), result.getHandle());
		assertEquals(user.getEmail(), result.getEmail());
		verify(testee).authenticate(handle, password);
		verify(testee).authenticate(any(User.class), eq(password));
		verify(testee).findUserByHandle(eq(handle));
		verify(testee, never()).findUserByEmail(eq(email));
		verify(testee).authenticateLDAP(eq(handle), eq(password));
	}
	
	@Test
	public void testAuthenticateWithEmail() throws Exception {
		
		// test data
		long userId = 123456L;
		User user = createTestUser(userId);
		String handle = user.getHandle();
		String email = user.getEmail();
		String password = user.getCredential().getPassword();
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.authenticate(anyString(), anyString())).thenCallRealMethod();
		when(testee.authenticate(any(User.class), anyString())).thenCallRealMethod();
		when(testee.findUserByHandle(handle)).thenReturn(user); // user exists in DB
		when(testee.findUserByEmail(email)).thenReturn(user);   // user exists in DB
		when(testee.authenticateLDAP(handle, password)).thenReturn(true); // user registered in LDAP

		// test#
		assertTrue(email + " is invalid for the test. This should be an email.", Utils.isEmail(email));
		User result = testee.authenticate(email, password);
		
		// verify#
		assertEquals(user.getHandle(), result.getHandle());
		assertEquals(user.getEmail(), result.getEmail());
		verify(testee).authenticate(email, password);
		verify(testee).authenticate(any(User.class), eq(password));
		verify(testee).findUserByEmail(eq(email));
		verify(testee, never()).findUserByHandle(eq(handle));
		verify(testee).authenticateLDAP(eq(handle), eq(password));
	}
	
	@Test
	public void testAuthenticateWithUserId() throws Exception {
		
		// test data
		long userId = 123456L;
		User user = createTestUser(userId);
		String handle = user.getHandle();
		String email = user.getEmail();
		String password = user.getCredential().getPassword();
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.authenticate(anyLong(), anyString())).thenCallRealMethod();
		when(testee.authenticate(any(User.class), anyString())).thenCallRealMethod();
		when(testee.findUserById(userId)).thenReturn(user); // user exists in DB
		when(testee.authenticateLDAP(handle, password)).thenReturn(true); // user registered in LDAP

		// test#
		assertTrue(email + " is invalid for the test. This should be an email.", Utils.isEmail(email));
		User result = testee.authenticate(userId, password);
		
		// verify#
		assertEquals(user.getHandle(), result.getHandle());
		assertEquals(user.getEmail(), result.getEmail());
		verify(testee).authenticate(userId, password);
		verify(testee).authenticate(any(User.class), eq(password));
		verify(testee).findUserById(eq(userId));
		verify(testee).authenticateLDAP(eq(handle), eq(password));
	}
	
	/*
	@Test
	public void testAuthenticate_IAEWhenHandleOrEmailIsNull() throws Exception {
		String password = "PASSWORD";
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).authenticate(anyString(), anyString());
		doCallRealMethod().when(testee).authenticate(anyLong(), anyString());
		// test
		try {
			// email is null
			testee.authenticate((String)null, password);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
		verify(testee, never()).authenticateLDAP(anyString(), anyString());
	}
	*/

	@Test
	public void testAuthenticate_IAEWhenPasswordIsNull() throws Exception {
		String email = "jdoe@example.com";
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).authenticate(anyString(), any());
		doCallRealMethod().when(testee).authenticate(anyLong(), any());
		// test
		try {
			// password is null
			testee.authenticate(email, null);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
		verify(testee, never()).authenticateLDAP(anyString(), anyString());
	}
	
	@Test
	public void testAuthenticate_NullWhenUserNotFoundInDB() throws Exception {
		
		// test data
		User user = createTestUser(123456L);
		String email = user.getEmail();
		String password = user.getCredential().getPassword();
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.authenticate(email, password)).thenCallRealMethod();
		when(testee.findUserByEmail(email)).thenReturn(null); // user is not found in DB

		// test
		User authedUser = testee.authenticate(email, password);
		
		// verify
		assertNull("The result of authenticate() should be null.", authedUser);
		
		verify(testee).findUserByEmail(eq(email));
		verify(testee, never()).authenticateLDAP(anyString(), anyString());
	}
		
	@Test
	public void testAuthenticate_NullWhenAuthenticationFailedWithLDAP() throws Exception {
		
		// test data
		User user = createTestUser(123456L);
		String handle = user.getHandle();
		String email = user.getEmail();
		String password = user.getCredential().getPassword();
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.authenticate(email, password)).thenCallRealMethod();
		when(testee.authenticate(any(User.class), eq(password))).thenCallRealMethod();
		when(testee.findUserByEmail(email)).thenReturn(user); // user exists in DB
		when(testee.authenticateLDAP(handle, password)).thenReturn(false); // authentication will be failed with the user.
		
		// test
		User authedUser = testee.authenticate(email, password);
		
		// verify
		assertNull("The result of authenticate() should be null.", authedUser);
		
		verify(testee).authenticate(email, password);
		verify(testee).authenticate(any(User.class), eq(password));
		verify(testee).findUserByEmail(eq(email));
		verify(testee).authenticateLDAP(eq(handle), eq(password));
	}
	
	@Test
	public void testAuthenticateLDAP() throws Exception {
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).authenticateLDAP(anyString(), anyString());
		doCallRealMethod().when(testee).setLdapService(any(LDAPService.class));
		
		// mock
		LDAPService ldapService = mock(LDAPService.class);
		testee.setLdapService(ldapService);
		
		// test data
		long userId = 123456L;
		User user = createTestUser(userId);

		// test
		testee.authenticateLDAP(user.getHandle(), user.getCredential().getPassword());
		
		// verify
		verify(ldapService).authenticateLDAPEntry(eq(user.getHandle()), eq(user.getCredential().getPassword()));
	}

	@Test
	public void testUpdateLastLoginDate() throws Exception {
		
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updateLastLoginDate(any(User.class));
		
		// test data
		long userId = 123456L;
		User user = createTestUser(userId);
		
		// test
		testee.updateLastLoginDate(user);
		
		// verify
		verify(testee).updateLastLogin(userId);
	}
	
	@Test
	public void testUpdatePassword() throws Exception {
		
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updatePassword(any(User.class));
		
		// test data
		long userId = 123456L;
		String newPassword = "passowrd123[]";
		User user = createTestUser(userId);
		user.getCredential().setPassword(newPassword);
		
		// test
		testee.updatePassword(user);
		
		// verify
		verify(testee).updatePassword(eq(user.getHandle()), eq(user.getCredential().getEncodedPassword()));
		verify(testee).updatePasswordLDAP(eq(userId), eq(newPassword));
	}
	
	@Test
	public void testUpdatePassword_IAEWhenUserIsNull() throws Exception {
		// test
		testUpdatePassword_IllegalArgument(null);
	}
	
	@Test
	public void testUpdatePassword_IAEWhenUserHasNoHandle() throws Exception {
		// test data
		User user = createTestUser(123456L);
		user.setHandle(null);

		// test
		testUpdatePassword_IllegalArgument(user);
	}

	@Test
	public void testUpdatePassword_IAEWhenUserHasNoPassword() throws Exception {
		// test data
		User user = createTestUser(123456L);
		user.getCredential().setPassword(null);

		// test
		testUpdatePassword_IllegalArgument(user);
	}

	private void testUpdatePassword_IllegalArgument(User user) {
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updatePassword(any(User.class));
		
		// test
		try {
			testee.updatePassword(user);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {}
		
		// verify
		verify(testee, never()).updatePassword(anyString(), anyString());
		verify(testee, never()).updatePasswordLDAP(anyLong(), anyString());
	}
	
	@Test
	public void testUpdatePasswordLDAP() throws Exception {
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).updatePasswordLDAP(anyLong(), anyString());
		doCallRealMethod().when(testee).setLdapService(any(LDAPService.class));
		
		// mock
		LDAPService ldapService = mock(LDAPService.class);
		testee.setLdapService(ldapService);
		
		// test data
		long userId = 123456L;
		User user = createTestUser(userId);

		// test
		testee.updatePasswordLDAP(userId, user.getCredential().getPassword());
		
		// verify
		verify(ldapService).changePasswordLDAPEntry(userId, user.getCredential().getPassword());
	}
	
	@Test
	public void testGetUserId_LDAPUserProfile() throws Exception {
		
		// data
		Long userId = 123456L;
		UserProfile profile = new UserProfile();
		profile.setProviderType(ProviderType.LDAP.name); // ad
		profile.setProvider("LDAP");
		profile.setUserId("LDAP|"+userId);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.getUserId(any(UserProfile.class))).thenCallRealMethod();
		
		// test
		Long result = testee.getUserId(profile);
		
		// verify result: userId should be extracted from profile.userId. (LDAP|{userId})
		assertEquals(userId, result);
	}
	
	@Test
	public void testGetUserId_Auth0UserProfile() throws Exception {

		// data
		Long userId = 123456L;
		UserProfile profile = new UserProfile();
		profile.setProviderType(ProviderType.AUTH0.name); // auth0
		profile.setProvider("TC-User-Database");
		profile.setUserId(userId.toString());
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.getUserId(any(UserProfile.class))).thenCallRealMethod();
		
		// test
		Long result = testee.getUserId(profile);
		
		// verify result: userId should be profile.userId.
		assertEquals(userId, result);
	}
	
	@Test
	public void testGetUserId_SocialAccountProfile() throws Exception {

		// data
		Long userId = 123456L;
		UserProfile profile = new UserProfile();
		profile.setProviderType(ProviderType.FACEBOOK.name); // facebook
		profile.setProvider(ProviderType.FACEBOOK.name);
		profile.setUserId(userId.toString());
		
		// mock
		SocialUserDAO socialUserDao = mock(SocialUserDAO.class);
		when(socialUserDao.findUserIdByProfile(profile)).thenReturn(userId);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.getUserId(any(UserProfile.class))).thenCallRealMethod();
		when(testee.createSocialUserDAO()).thenReturn(socialUserDao);
		
		// test
		Long result = testee.getUserId(profile);
		
		// verify result: userId should be profile.userId.
		assertEquals(userId, result);
		
		// verify mock
		verify(socialUserDao).findUserIdByProfile(profile);
		verify(testee).createSocialUserDAO();
	}
	
	@Test
	public void testGetUserId_SSOAccountProfile() throws Exception {

		// data
		Long userId = 123456L;
		UserProfile profile = new UserProfile();
		profile.setProviderType(ProviderType.SAMLP.name); // samlp
		profile.setProvider("samlp-connection"); // connection name
		profile.setUserId(userId.toString());
		
		// mock
		SSOUserDAO ssoUserDao = mock(SSOUserDAO.class);
		when(ssoUserDao.findUserIdByProfile(profile)).thenReturn(userId);
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.getUserId(any(UserProfile.class))).thenCallRealMethod();
		when(testee.createSSOUserDAO()).thenReturn(ssoUserDao);
		
		// test
		Long result = testee.getUserId(profile);
		
		// verify result: userId should be profile.userId.
		assertEquals(userId, result);
		
		// verify mock
		verify(ssoUserDao).findUserIdByProfile(profile);
		verify(testee).createSSOUserDAO();
	}
	
	@Test
	public void testGetUserId_Err_WhenProfileHasUnknownProviderType() throws Exception {
		
		// data
		Long userId = 123456L;
		UserProfile profile = new UserProfile();
		profile.setProviderType("unknown");
		profile.setProvider("unknown");
		profile.setUserId(userId.toString());
		
		//testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.getUserId(any(UserProfile.class))).thenCallRealMethod();
		
		// test
		try{
			testee.getUserId(profile);
			fail("IllegalArgumentException should be thrown in the provious step.");
		} catch(IllegalArgumentException e) {}
	}
	
	@Test
	public void testGetUserId_Err_WhenLDAPOrAuth0ProfileDoesNotContainValidUserId() throws Exception {
		
		// data
		UserProfile profileLDAP = new UserProfile();
		profileLDAP.setProviderType(ProviderType.LDAP.name);
		profileLDAP.setProvider("LDAP");
		profileLDAP.setUserId("InvalidUserId");

		UserProfile profileAuth0 = new UserProfile();
		profileAuth0.setProviderType(ProviderType.AUTH0.name);
		profileAuth0.setProvider("TC-User-Database");
		profileAuth0.setUserId("InvalidUserId");

		//testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.getUserId(any(UserProfile.class))).thenCallRealMethod();
		
		// test
		try{
			testee.getUserId(profileLDAP);
			fail("IllegalArgumentException should be thrown in the provious step.");
		} catch(IllegalArgumentException e) {}
		// test
		try{
			testee.getUserId(profileAuth0);
			fail("IllegalArgumentException should be thrown in the provious step.");
		} catch(IllegalArgumentException e) {}
	}
	
	@Test
	public void testGenerateSSOToken() throws Exception {
		// data
		Long userId = 123456L;
		String password = "1234567890";
		User user = new User();
		user.setId(new TCID(userId));
		user.setHandle("jdoe");
		user.setStatus("A");
		user.setCredential(new Credential());
		user.getCredential().setPassword(password);
		String encPassword = user.getCredential().getEncodedPassword();
		String ssoToken = "SSO-TOKEN-DUMMY";
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		when(testee.generateSSOToken(userId)).thenCallRealMethod();
		// mock
		when(testee.findUserById(userId)).thenReturn(user);
		when(testee.generateSSOToken(userId, encPassword, "A")).thenReturn(ssoToken);
		
		// test
		String result = testee.generateSSOToken(userId);

		// verify
		assertNotNull(result);
		assertEquals(ssoToken, result);
		verify(testee).findUserById(userId);
		verify(testee).generateSSOToken(userId, encPassword, "A");
	}
	
	@Test
	public void testGenerateSSOToken2() throws Exception {
		
		// data
		Long userId = 123456L;
		String password = "PASSWORD-HASH-DUMMY";
		String status = "A";
		String salt = "SALT";
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doReturn(salt).when(testee).getSSOTokenSalt();
		when(testee.generateSSOToken(userId, password, status)).thenCallRealMethod();
		
		// test
		String result = testee.generateSSOToken(userId, password, status);
		
		// verify result
		assertNotNull(result);
		String[] parts = result.split("\\|");
		
		assertEquals(2, parts.length);
		assertEquals(String.valueOf(userId), parts[0]);
		
		// @see UserDAO#generateSSOToken(Long, String, String)
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] plain = (salt + userId + password + status).getBytes("UTF-8");
        byte[] raw = md.digest(plain);
        StringBuffer hash = new StringBuffer();
        for (byte aRaw : raw)
        	hash.append(Integer.toHexString(aRaw & 0xff));
        
        assertEquals(hash.toString(), parts[1]);
	}
	
	@Test
	public void testGetSSOTokenSalt() {
		// data
		String salt = "SALT-DUMMY";
		Map<String, Object> ctx = new HashMap<String, Object>();
		ctx.put("ssoTokenSalt", salt);
		Utils.setApplicationContext(ctx);
		
		// testee
		UserDAO testee = mock(UserDAO.class);
		doCallRealMethod().when(testee).getSSOTokenSalt();

		// test1
		String result = testee.getSSOTokenSalt();
		
		assertEquals(salt, result);
		
		
		// data
		ctx.clear();
		Utils.setApplicationContext(ctx);

		// test2
		String result2 = testee.getSSOTokenSalt();
		
		assertNull(result2);

	}
	
	protected User createTestUser(long userId) {
		User user = new User();
		user.setId(new TCID(userId));
		user.setHandle("jdoe");
		user.setEmail("jdoe@examples.com");
		user.setActive(false);
		user.setEmailStatus(2); // 1:active, other:inactive
		user.setCredential(new Credential());
		user.getCredential().setPassword("passwd123[]");
		user.getCredential().setActivationCode(Utils.getActivationCode(userId));
		user.setCountry(new Country());
		user.getCountry().setName("United States");
		return user;
	}
}
