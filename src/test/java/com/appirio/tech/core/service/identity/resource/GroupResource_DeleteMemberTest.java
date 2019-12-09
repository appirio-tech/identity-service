/**
 * Copyright (C) 2017 Topcoder Inc., All Rights Reserved.
 */
package com.appirio.tech.core.service.identity.resource;

import static java.net.HttpURLConnection.HTTP_FORBIDDEN;
import static java.net.HttpURLConnection.HTTP_OK;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import javax.servlet.http.HttpServletRequest;

import org.joda.time.DateTime;
import org.junit.Test;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.request.PostPutRequest;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.dao.GroupDAO;
import com.appirio.tech.core.service.identity.representation.Group;
import com.appirio.tech.core.service.identity.representation.GroupMembership;
import com.appirio.tech.core.service.identity.representation.GroupMembership.MembershipType;
import com.appirio.tech.core.service.identity.util.Utils;

/**
 * Unit tests for {@link GroupResource#removeMember(AuthUser, TCID, TCID, HttpServletRequest)}.
 *
 * @author TCSCODER
 * @version 1.0
 */
@SuppressWarnings("unchecked")
public class GroupResource_DeleteMemberTest extends GroupResourceTestBase {

	/**
	 * Member should be deleted successfully.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testRemoveMember_OK() throws Exception {
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// data
		TCID groupId = new TCID(123);
		TCID memberId = new TCID(1);
		Group group = createGroup("TestGroup", "Test Group");
		PostPutRequest<GroupMembership> postRequest = (PostPutRequest<GroupMembership>)mock(PostPutRequest.class);
		GroupMembership member = createGroupMembership(Utils.toLongValue(groupId), Utils.toLongValue(memberId));
		doReturn(member).when(postRequest).getParam();

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(group).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(member).when(groupDao).findMembership(Utils.toLongValue(memberId));

		// testee
		GroupResource testee = createGroupResourceMock(groupDao);

		// test
		ApiResponse result = testee.removeMember(authUser, groupId, memberId, request);

		// checking result
		checkApiResponseHeader(result, HTTP_OK);

		GroupMembership content = (GroupMembership)result.getResult().getContent();
		assertNotNull("A content in the result should not be null.", content);
		assertEquals(member.getMemberId(), content.getMemberId());
		assertEquals(member.getMembershipType(), content.getMembershipType());
		assertEquals(member.getCreatedBy(), content.getCreatedBy());
		assertNotNull(content.getCreatedAt());

		verify(groupDao).removeMembership(Utils.toLongValue(memberId));
		verify(authUser, atLeastOnce()).getRoles();
	}

	/**
	 * The user is not an admin, 403 HTTP_FORBIDDEN response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testRemoveMember_ERR_WhenUserIsNotAdmin() throws Exception {
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);
		// data
		TCID groupId = new TCID(123);
		TCID memberId = new TCID(1);
		Group group = createGroup("TestGroup", "Test Group");
		PostPutRequest<GroupMembership> postRequest = (PostPutRequest<GroupMembership>)mock(PostPutRequest.class);
		GroupMembership member = createGroupMembership(Utils.toLongValue(groupId), Utils.toLongValue(memberId));
		doReturn(member).when(postRequest).getParam();

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(group).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(member).when(groupDao).findMembership(Utils.toLongValue(memberId));

		// test
		try {
			createGroupResourceMock(groupDao).removeMember(authUser, groupId, memberId, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_FORBIDDEN, e.getHttpStatus());
		}

		verify(groupDao, never()).create(any(Group.class));
	}

	/**
	 * Member should be removed successfully if they self remove themselves from a group that allows this.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testRemoveMember_OK_WhenNonAdminMemberSelfRegisters() throws Exception {
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);
		// data
		TCID groupId = new TCID(123);
		Group group = createGroup("TestGroup", "Test Group");
		group.setSelfRegister(true);
		PostPutRequest<GroupMembership> postRequest = (PostPutRequest<GroupMembership>)mock(PostPutRequest.class);
		GroupMembership member = createGroupMembership(Utils.toLongValue(groupId), Utils.toLongValue(userId));
		doReturn(member).when(postRequest).getParam();

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(group).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(member).when(groupDao).findMembership(Utils.toLongValue(userId));

		// testee
		GroupResource testee = createGroupResourceMock(groupDao);

		// test
		ApiResponse result = testee.removeMember(authUser, groupId, userId, request);

		// checking result
		checkApiResponseHeader(result, HTTP_OK);

		GroupMembership content = (GroupMembership)result.getResult().getContent();
		assertNotNull("A content in the result should not be null.", content);
		assertEquals(member.getMemberId(), content.getMemberId());
		assertEquals(member.getMembershipType(), content.getMembershipType());
		assertEquals(member.getCreatedBy(), content.getCreatedBy());
		assertNotNull(content.getCreatedAt());

		verify(groupDao).removeMembership(Utils.toLongValue(userId));
		verify(authUser, atLeastOnce()).getRoles();
	}
}
