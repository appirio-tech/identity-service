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
 * Unit tests for {@link GroupResource#addMember(AuthUser, TCID, PostPutRequest<GroupMembership>, HttpServletRequest)}.
 *
 * @author TCSCODER
 * @version 1.0
 */
@SuppressWarnings("unchecked")
public class GroupResource_AddMemberTest extends GroupResourceTestBase {

	/**
	 * Member should be added successfully.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testAddMember_OK() throws Exception {
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// data
		TCID groupId = new TCID(123);
		Group group = createGroup("TestGroup", "Test Group");
		PostPutRequest<GroupMembership> postRequest = (PostPutRequest<GroupMembership>)mock(PostPutRequest.class);
		GroupMembership member = createGroupMembership(Utils.toLongValue(groupId), Utils.toLongValue(userId));
		doReturn(member).when(postRequest).getParam();

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(group).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(member).when(groupDao).addMembership(member);

		// testee
		GroupResource testee = createGroupResourceMock(groupDao);

		// test
		ApiResponse result = testee.addMember(authUser, groupId, postRequest, request);

		// checking result
		checkApiResponseHeader(result, HTTP_OK);

		GroupMembership content = (GroupMembership)result.getResult().getContent();
		assertNotNull("A content in the result should not be null.", content);
		assertEquals(member.getMemberId(), content.getMemberId());
		assertEquals(member.getMembershipType(), content.getMembershipType());
		assertEquals(userId, content.getCreatedBy());
		assertNotNull(content.getCreatedAt());

		verify(groupDao).addMembership(member);
		verify(authUser, atLeastOnce()).getUserId();
		verify(authUser, atLeastOnce()).getRoles();
	}

	/**
	 * TThe user is not an admin, 403 HTTP_FORBIDDEN response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testAddMember_ERR_WhenUserIsNotAdmin() throws Exception {
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);
		// data
		TCID groupId = new TCID(123);
		Group group = createGroup("TestGroup", "Test Group");
		PostPutRequest<GroupMembership> postRequest = (PostPutRequest<GroupMembership>)mock(PostPutRequest.class);
		GroupMembership member = createGroupMembership(Utils.toLongValue(groupId), Utils.toLongValue(userId));
		doReturn(member).when(postRequest).getParam();

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(group).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(member).when(groupDao).addMembership(member);

		// test
		try {
			createGroupResourceMock(groupDao).addMember(authUser, groupId, postRequest, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_FORBIDDEN, e.getHttpStatus());
		}

		verify(groupDao, never()).create(any(Group.class));
	}

	/**
	 * Member should be added successfully if he self registers to a group that allows this.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testAddMember_OK_WhenNonAdminMemberSelfRegisters() throws Exception {
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
		doReturn(member).when(groupDao).addMembership(member);

		// testee
		GroupResource testee = createGroupResourceMock(groupDao);

		// test
		ApiResponse result = testee.addMember(authUser, groupId, postRequest, request);

		// checking result
		checkApiResponseHeader(result, HTTP_OK);

		GroupMembership content = (GroupMembership)result.getResult().getContent();
		assertNotNull("A content in the result should not be null.", content);
		assertEquals(member.getMemberId(), content.getMemberId());
		assertEquals(member.getMembershipType(), content.getMembershipType());
		assertEquals(userId, content.getCreatedBy());
		assertNotNull(content.getCreatedAt());

		verify(groupDao).addMembership(member);
		verify(authUser, atLeastOnce()).getUserId();
		verify(authUser, atLeastOnce()).getRoles();
	}
}
