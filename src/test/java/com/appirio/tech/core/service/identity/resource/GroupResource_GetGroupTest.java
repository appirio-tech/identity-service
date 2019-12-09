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
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.joda.time.DateTime;
import org.junit.Test;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.request.FieldSelector;
import com.appirio.tech.core.api.v3.response.ApiFieldSelectorResponse;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.dao.GroupDAO;
import com.appirio.tech.core.service.identity.representation.Group;
import com.appirio.tech.core.service.identity.representation.GroupMembership;
import com.appirio.tech.core.service.identity.util.Utils;

/**
 * Unit tests for {@link GroupResource#getObject(AuthUser, TCID, FieldSelector, HttpServletRequest)}.
 *
 * <p>
 * Version 1.1 - GROUPS API ENHANCEMENTS
 * - Add unit tests for new scenarios that depend on the "privateGroup" and "selfRegister" fields
 * </p>
 *
 * @author TCSCODER
 * @version 1.1
 */
public class GroupResource_GetGroupTest extends GroupResourceTestBase {

	/**
	 * Group should be retrieved properly.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testGetObject_OK() throws Exception {
		// data
		TCID groupId = new TCID(123);
		Group existingGroup = createGroup(groupId, "TestGroup", "Test Group", new TCID(111), DateTime.now(),
				new TCID(222), DateTime.now());

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(existingGroup).when(groupDao).findGroupById(Utils.toLongValue(groupId));

		// testee
		GroupResource testee = createGroupResourceMock(groupDao);

		// test
		ApiResponse result = testee.getObject(authUser, groupId, null, request);

		// checking result
		checkApiResponseHeader(result, HTTP_OK);

		Group content = (Group)result.getResult().getContent();
		assertNotNull("A content in the result should not be null.", content);
		assertEquals(existingGroup.getId().getId(), content.getId().getId());
		assertEquals(existingGroup.getName(), content.getName());
		assertEquals(existingGroup.getDescription(), content.getDescription());
		assertEquals(existingGroup.getCreatedBy(), content.getCreatedBy());
		assertEquals(existingGroup.getCreatedAt(), content.getCreatedAt());
		assertEquals(existingGroup.getModifiedAt(), content.getModifiedAt());
		assertEquals(existingGroup.getModifiedBy(), content.getModifiedBy());

		verify(groupDao).findGroupById(Utils.toLongValue(groupId));
	}

	/**
	 * Group should be retrieved properly with fields selector.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testGetObject_OK_Fields() throws Exception {
		// data
		TCID groupId = new TCID(123);
		Group existingGroup = createGroup(groupId, "TestGroup", "Test Group", new TCID(111), DateTime.now(),
				new TCID(222), DateTime.now());

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(existingGroup).when(groupDao).findGroupById(Utils.toLongValue(groupId));

		// testee
		GroupResource testee = createGroupResourceMock(groupDao);

		// test
		FieldSelector selector = new FieldSelector();
		selector.addField("name");
		selector.addField("description");
		ApiResponse result = testee.getObject(authUser, groupId, selector, request);

		// checking result
		checkApiResponseHeader(result, HTTP_OK);

		Group content = (Group)result.getResult().getContent();
		assertNotNull("A content in the result should not be null.", content);
		assertEquals(existingGroup.getId().getId(), content.getId().getId());
		assertEquals(existingGroup.getName(), content.getName());
		assertEquals(existingGroup.getDescription(), content.getDescription());
		assertEquals(existingGroup.getCreatedBy(), content.getCreatedBy());
		assertEquals(existingGroup.getCreatedAt(), content.getCreatedAt());
		assertEquals(existingGroup.getModifiedAt(), content.getModifiedAt());
		assertEquals(existingGroup.getModifiedBy(), content.getModifiedBy());

		Set<String> serializeFields = ((ApiFieldSelectorResponse) result).getFieldSelectionMap()
				.get(Integer.valueOf(System.identityHashCode(content)));
		assertEquals(2, serializeFields.size());
		assertTrue(serializeFields.contains("name"));
		assertTrue(serializeFields.contains("description"));
		verify(groupDao).findGroupById(Utils.toLongValue(groupId));
	}

	/**
	 * Group id is invalid, 400 HTTP_BAD_REQUEST response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testGetObject_ERR_WhenGroupIdInvalid() throws Exception {

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);

		// test
		try {
			createGroupResourceMock(groupDao).getObject(authUser, new TCID("invalid"), null, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
		}

		verify(groupDao, never()).findGroupById(any(Long.class));
	}

	/**
	 * Group does not exist, 404 HTTP_NOT_FOUND response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testGetObject_ERR_WhenGroupDoesNotExists() throws Exception {
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
			createGroupResourceMock(groupDao).getObject(authUser, groupId, null, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_NOT_FOUND, e.getHttpStatus());
		}

		verify(groupDao).findGroupById(Utils.toLongValue(groupId));
	}

	/**
	 * The group is private and the user is not an admin or a member, 403 HTTP_FORBIDDEN response should be returned.
	 * @throws Exception to JUnit
	 * @since 1.1
	 */
	@Test
	public void testGetObject_ERR_WhenUserIsNotAdminOrMemberPrivateGroup() throws Exception {
		// data
		TCID groupId = new TCID(123);

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		Group existingGroup = createGroup(groupId, "TestGroup", "Test Group", new TCID(111), DateTime.now(),
				new TCID(222), DateTime.now());
		existingGroup.setPrivateGroup(true);
		doReturn(existingGroup).when(groupDao).findGroupById(Utils.toLongValue(groupId));

		// test
		try {
			createGroupResourceMock(groupDao).getObject(authUser, groupId, null, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_FORBIDDEN, e.getHttpStatus());
		}

		verify(groupDao).findGroupById(Utils.toLongValue(groupId));
	}

	/**
	 * The group is private and the user is a member, group should be retrieved properly.
	 * @throws Exception to JUnit
	 * @since 1.1
	 */
	@Test
	public void testGetObject_OK_WhenUserIsMemberPrivateGroup() throws Exception {
		// data
		TCID groupId = new TCID(123);

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		Group existingGroup = createGroup(groupId, "TestGroup", "Test Group", new TCID(111), DateTime.now(),
				new TCID(222), DateTime.now());
		existingGroup.setPrivateGroup(true);
		doReturn(existingGroup).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		List<GroupMembership> memberships = new ArrayList<GroupMembership>();
		GroupMembership groupMembership = new GroupMembership();
		groupMembership.setGroupId(Utils.toLongValue(groupId));
		groupMembership.setMemberId(Utils.toLongValue(authUser.getUserId()));
		memberships.add(groupMembership);
		doReturn(memberships).when(groupDao).findMembershipsByGroup(Utils.toLongValue(groupId));
		when(groupDao.checkMemberOfGroup(Utils.toLongValue(authUser.getUserId()), Utils.toLongValue(groupId))).thenReturn(1);

		// testee
		GroupResource testee = createGroupResourceMock(groupDao);

		// test
		ApiResponse result = testee.getObject(authUser, groupId, null, request);

		// checking result
		checkApiResponseHeader(result, HTTP_OK);

		Group content = (Group)result.getResult().getContent();
		assertNotNull("A content in the result should not be null.", content);
		assertEquals(existingGroup.getId().getId(), content.getId().getId());
		assertEquals(existingGroup.getName(), content.getName());
		assertEquals(existingGroup.getDescription(), content.getDescription());
		assertEquals(existingGroup.getCreatedBy(), content.getCreatedBy());
		assertEquals(existingGroup.getCreatedAt(), content.getCreatedAt());
		assertEquals(existingGroup.getModifiedAt(), content.getModifiedAt());
		assertEquals(existingGroup.getModifiedBy(), content.getModifiedBy());

		verify(groupDao).findGroupById(Utils.toLongValue(groupId));
	}

	/**
	 * The group is public, group should be retrieved properly.
	 * @throws Exception to JUnit
	 * @since 1.1
	 */
	@Test
	public void testGetObject_OK_WhenGroupIsPublic() throws Exception {
		// data
		TCID groupId = new TCID(123);

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		Group existingGroup = createGroup(groupId, "TestGroup", "Test Group", new TCID(111), DateTime.now(),
				new TCID(222), DateTime.now());
		existingGroup.setPrivateGroup(false);
		doReturn(existingGroup).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		List<GroupMembership> memberships = new ArrayList<GroupMembership>();
		GroupMembership groupMembership = new GroupMembership();
		groupMembership.setGroupId(Utils.toLongValue(groupId));
		groupMembership.setMemberId(Utils.toLongValue(authUser.getUserId()));
		memberships.add(groupMembership);
		doReturn(memberships).when(groupDao).findMembershipsByGroup(Utils.toLongValue(groupId));

		// testee
		GroupResource testee = createGroupResourceMock(groupDao);

		// test
		ApiResponse result = testee.getObject(authUser, groupId, null, request);

		// checking result
		checkApiResponseHeader(result, HTTP_OK);

		Group content = (Group)result.getResult().getContent();
		assertNotNull("A content in the result should not be null.", content);
		assertEquals(existingGroup.getId().getId(), content.getId().getId());
		assertEquals(existingGroup.getName(), content.getName());
		assertEquals(existingGroup.getDescription(), content.getDescription());
		assertEquals(existingGroup.getCreatedBy(), content.getCreatedBy());
		assertEquals(existingGroup.getCreatedAt(), content.getCreatedAt());
		assertEquals(existingGroup.getModifiedAt(), content.getModifiedAt());
		assertEquals(existingGroup.getModifiedBy(), content.getModifiedBy());

		verify(groupDao).findGroupById(Utils.toLongValue(groupId));
	}
}
