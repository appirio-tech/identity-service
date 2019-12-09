/**
 * Copyright (C) 2017 Topcoder Inc., All Rights Reserved.
 */
package com.appirio.tech.core.service.identity.resource;

import static java.net.HttpURLConnection.HTTP_BAD_REQUEST;
import static java.net.HttpURLConnection.HTTP_FORBIDDEN;
import static java.net.HttpURLConnection.HTTP_NOT_FOUND;
import static java.net.HttpURLConnection.HTTP_OK;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import java.util.LinkedList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.joda.time.DateTime;
import org.junit.Test;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.dao.GroupDAO;
import com.appirio.tech.core.service.identity.representation.Group;
import com.appirio.tech.core.service.identity.representation.GroupMembership;
import com.appirio.tech.core.service.identity.representation.GroupMembership.MembershipType;
import com.appirio.tech.core.service.identity.util.Utils;

/**
 * Unit tests for {@link GroupResource#getMembers(AuthUser, TCID, HttpServletRequest)}.
 *
 * <p>
 * Version 1.1 - GROUPS API ENHANCEMENTS
 * - Add unit tests for new scenarios that depend on the "privateGroup" and "selfRegister" fields
 * </p>
 *
 * @author TCSCODER
 * @version 1.1
 */
@SuppressWarnings("unchecked")
public class GroupResource_GetMembersTest extends GroupResourceTestBase {

	/**
	 * Create members.
	 *
	 * @param groupId the group id
	 * @param count the count
	 * @return list of members
	 */
	private List<GroupMembership> createGroupMembership(long groupId, int count) {
		// data
		List<GroupMembership> members = new LinkedList<>();
		for(long i=0; i<count; i++) {
			long n = i+1;
			GroupMembership member = new GroupMembership();
			member.setId(new TCID(n));
			member.setGroupId(groupId);
			member.setMemberId(n);
			member.setMembershipType(MembershipType.User.lowerName());
			member.setCreatedAt(DateTime.now());
			member.setCreatedBy(new TCID(111));
			members.add(member);
		}
		return members;
	}

	/**
	 * Members should be retrieved properly.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testGetMembers_OK() throws Exception {
		// data
		TCID groupId = new TCID(123);
		Group group = createGroup("TestGroup", "Test Group");
		List<GroupMembership> members = createGroupMembership(Utils.toLongValue(groupId), 3);

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(group).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(members).when(groupDao).findMembershipsByGroup(Utils.toLongValue(groupId));

		// testee
		GroupResource testee = createGroupResourceMock(groupDao);

		// test
		ApiResponse result = testee.getMembers(authUser, groupId, request);

		// checking result
		checkApiResponseHeader(result, HTTP_OK);

		List<GroupMembership> content = (List<GroupMembership>)result.getResult().getContent();
		assertNotNull("A content in the result should not be null.", content);
		assertEquals(members.size(), content.size());
		for (int i = 0; i < members.size(); i++) {
			assertEquals(members.get(i), content.get(i));
		}

		verify(groupDao).findGroupById(Utils.toLongValue(groupId));
		verify(groupDao).findMembershipsByGroup(Utils.toLongValue(groupId));
	}

	/**
	 * Group id is invalid, 400 HTTP_BAD_REQUEST response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testGetMembers_ERR_WhenGroupIdInvalid() throws Exception {

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);

		// test
		try {
			createGroupResourceMock(groupDao).getMembers(authUser, new TCID("invalid"), request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
		}

		verify(groupDao, never()).findGroupById(any(Long.class));
		verify(groupDao, never()).findMembershipsByGroup(any(Long.class));
	}

	/**
	 * Group does not exist, 404 HTTP_NOT_FOUND response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testGetMembers_ERR_WhenGroupDoesNotExists() throws Exception {
		// data
		TCID groupId = new TCID(123);

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(null).when(groupDao).findGroupById(Utils.toLongValue(groupId));

		// test
		try {
			createGroupResourceMock(groupDao).getMembers(authUser, groupId, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_NOT_FOUND, e.getHttpStatus());
		}

		verify(groupDao).findGroupById(Utils.toLongValue(groupId));
		verify(groupDao, never()).findMembershipsByGroup(any(Long.class));
	}

	/**
	 * The group is private and the user is not an admin or a member, 403 HTTP_FORBIDDEN response should be returned.
	 * @throws Exception to JUnit
	 * @since 1.1
	 */
	@Test
	public void testGetMembers_ERR_WhenUserIsNotAdminOrMemberPrivateGroup() throws Exception {
		// data
		TCID groupId = new TCID(123);
		Group group = createGroup("TestGroup", "Test Group");
		group.setId(groupId);
		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(group).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		when(groupDao.checkMemberOfGroup(Utils.toLongValue(authUser.getUserId()), Utils.toLongValue(groupId))).thenReturn(0);

		// test
		try {
			createGroupResourceMock(groupDao).getMembers(authUser, groupId, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_FORBIDDEN, e.getHttpStatus());
		}

		verify(groupDao).findGroupById(Utils.toLongValue(groupId));
		verify(groupDao, never()).findMembershipsByGroup(any(Long.class));
	}

	/**
	 * The group is public, members should be retrieved properly.
	 * @throws Exception to JUnit
	 * @since 1.1
	 */
	@Test
	public void testGetMembers_OK_WhenGroupIsPublic() throws Exception {
		// data
		TCID groupId = new TCID(123);
		Group group = createGroup("TestGroup", "Test Group");
		group.setId(groupId);
		group.setPrivateGroup(false);
		List<GroupMembership> members = createGroupMembership(Utils.toLongValue(groupId), 3);

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(group).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(members).when(groupDao).findMembershipsByGroup(Utils.toLongValue(groupId));
		when(groupDao.checkMemberOfGroup(Utils.toLongValue(authUser.getUserId()), Utils.toLongValue(groupId))).thenReturn(0);

		// testee
		GroupResource testee = createGroupResourceMock(groupDao);

		// test
		ApiResponse result = testee.getMembers(authUser, groupId, request);

		// checking result
		checkApiResponseHeader(result, HTTP_OK);

		List<GroupMembership> content = (List<GroupMembership>)result.getResult().getContent();
		assertNotNull("A content in the result should not be null.", content);
		assertEquals(members.size(), content.size());
		for (int i = 0; i < members.size(); i++) {
			assertEquals(members.get(i), content.get(i));
		}

		verify(groupDao).findGroupById(Utils.toLongValue(groupId));
		verify(groupDao).findMembershipsByGroup(Utils.toLongValue(groupId));
	}

	/**
	 * The group is private and the user is a member, members should be retrieved properly.
	 * @throws Exception to JUnit
	 * @since 1.1
	 */
	@Test
	public void testGetMembers_OK_WhenUserIsMemberPrivateGroup() throws Exception {
		// data
		TCID groupId = new TCID(123);
		Group group = createGroup("TestGroup", "Test Group");
		group.setId(groupId);
		group.setPrivateGroup(false);
		List<GroupMembership> members = createGroupMembership(Utils.toLongValue(groupId), 3);

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(group).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(members).when(groupDao).findMembershipsByGroup(Utils.toLongValue(groupId));
		when(groupDao.checkMemberOfGroup(Utils.toLongValue(authUser.getUserId()), Utils.toLongValue(groupId))).thenReturn(1);

		// testee
		GroupResource testee = createGroupResourceMock(groupDao);

		// test
		ApiResponse result = testee.getMembers(authUser, groupId, request);

		// checking result
		checkApiResponseHeader(result, HTTP_OK);

		List<GroupMembership> content = (List<GroupMembership>)result.getResult().getContent();
		assertNotNull("A content in the result should not be null.", content);
		assertEquals(members.size(), content.size());
		for (int i = 0; i < members.size(); i++) {
			assertEquals(members.get(i), content.get(i));
		}

		verify(groupDao).findGroupById(Utils.toLongValue(groupId));
		verify(groupDao).findMembershipsByGroup(Utils.toLongValue(groupId));
	}

}
