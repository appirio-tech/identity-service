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
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.RandomStringUtils;
import org.joda.time.DateTime;
import org.junit.Test;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.request.PostPutRequest;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.dao.GroupDAO;
import com.appirio.tech.core.service.identity.representation.Group;
import com.appirio.tech.core.service.identity.util.Utils;

/**
 * Unit tests for {@link GroupResource#updateObject(AuthUser, String, PostPutRequest, HttpServletRequest)}.
 *
 * @author TCSCODER
 * @version 1.0
 */
@SuppressWarnings("unchecked")
public class GroupResource_UpdateGroupTest extends GroupResourceTestBase {

	/**
	 * Group should be updated properly.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testUpdateObject_OK() throws Exception {
		// data
		TCID groupId = new TCID(123);
		Group group = createGroup("TestGroup", "Test Group");
		Group existingGroup = createGroup(groupId, "TestGroup", "Test Group", new TCID(111), DateTime.now(), null, null);
		
		// mock (PostPutRequest)
		PostPutRequest<Group> postRequest = (PostPutRequest<Group>)mock(PostPutRequest.class);
		doReturn(group).when(postRequest).getParam();
		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(existingGroup).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(groupId).when(groupDao).update(group);
		
		// testee
		GroupResource testee = createGroupResourceMock(groupDao);
		
		// test
		ApiResponse result = testee.updateObject(authUser, groupId.getId(), postRequest, request);
		
		// checking result
		checkApiResponseHeader(result, HTTP_OK);
		
		Group content = (Group)result.getResult().getContent();	 
		assertNotNull("A content in the result should not be null.", content);
		assertEquals(groupId.getId(), content.getId().getId());
		assertEquals(group.getName(), content.getName());
		assertEquals(group.getDescription(), content.getDescription());
		assertEquals(existingGroup.getCreatedBy(), content.getCreatedBy());
		assertEquals(existingGroup.getCreatedAt(), content.getCreatedAt());
		assertEquals(userId, content.getModifiedBy());
		assertNotNull(content.getModifiedAt());
		
		verify(postRequest).getParam();
		verify(groupDao).findGroupById(Utils.toLongValue(groupId));
		verify(groupDao).update(group);
		verify(authUser, atLeastOnce()).getUserId();
		verify(authUser, atLeastOnce()).getRoles();
	}

	/**
	 * User is not admin, 403 HTTP_FORBIDDEN response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testUpdateObject_ERR_WhenUserIsNotAdmin() throws Exception {

		// mock (PostPutRequest)
		PostPutRequest<Group> postRequest = (PostPutRequest<Group>)mock(PostPutRequest.class);
		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);

		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);

		// test
		try {
			createGroupResourceMock(groupDao).updateObject(authUser, "123", postRequest, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_FORBIDDEN, e.getHttpStatus());
		}

		verify(groupDao, never()).findGroupById(any(Long.class));
		verify(groupDao, never()).update(any(Group.class));
	}

	/**
	 * Group id is invalid, 400 HTTP_BAD_REQUEST response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testUpdateObject_ERR_WhenGroupIdInvalid() throws Exception {

		// data
		TCID groupId = new TCID("invalid"); // group id is invalid
		Group group = createGroup("TestGroup", "Test Group");
		
		// mock (PostPutRequest)
		PostPutRequest<Group> postRequest = (PostPutRequest<Group>)mock(PostPutRequest.class);
		doReturn(group).when(postRequest).getParam();
		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);

		// test
		try {
			createGroupResourceMock(groupDao).updateObject(authUser, groupId.getId(), postRequest, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
		}

		verify(groupDao, never()).findGroupById(any(Long.class));
		verify(groupDao, never()).update(any(Group.class));
	}

	/**
	 * Request null, 400 HTTP_BAD_REQUEST response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testUpdateObject_ERR_WhenRequestIsNull() throws Exception {

		// data
		TCID groupId = new TCID(123);
		Group group = createGroup(null, "Test Group"); // name is mandatory
		
		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(group).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(groupId).when(groupDao).update(group);

		// test
		try {
			createGroupResourceMock(groupDao).updateObject(authUser, groupId.getId(), null, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
		}

		verify(groupDao, never()).findGroupById(any(Long.class));
		verify(groupDao, never()).update(any(Group.class));
	}

	/**
	 * Group is null, 400 HTTP_BAD_REQUEST response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testUpdateObject_ERR_WhenGroupIsNull() throws Exception {

		// data
		TCID groupId = new TCID(123);
		Group group = createGroup(null, "Test Group"); // name is mandatory
		
		// mock (PostPutRequest)
		PostPutRequest<Group> postRequest = (PostPutRequest<Group>)mock(PostPutRequest.class);
		doReturn(null).when(postRequest).getParam();
		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(group).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(groupId).when(groupDao).update(group);

		// test
		try {
			createGroupResourceMock(groupDao).updateObject(authUser, groupId.getId(), postRequest, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
		}

		verify(groupDao, never()).findGroupById(any(Long.class));
		verify(groupDao, never()).update(any(Group.class));
	}

	/**
	 * Group name is null, 400 HTTP_BAD_REQUEST response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testUpdateObject_ERR_WhenNameIsNull() throws Exception {

		// data
		TCID groupId = new TCID(123);
		Group group = createGroup(null, "Test Group"); // name is mandatory
		
		// mock (PostPutRequest)
		PostPutRequest<Group> postRequest = (PostPutRequest<Group>)mock(PostPutRequest.class);
		doReturn(group).when(postRequest).getParam();
		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(group).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(groupId).when(groupDao).update(group);

		// test
		try {
			createGroupResourceMock(groupDao).updateObject(authUser, groupId.getId(), postRequest, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
		}

		verify(groupDao, never()).findGroupById(any(Long.class));
		verify(groupDao, never()).update(any(Group.class));
	}

	/**
	 * Group name is too short, 400 HTTP_BAD_REQUEST response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testUpdateObject_ERR_WhenNameIsTooShort() throws Exception {

		// data
		TCID groupId = new TCID(123);
		Group group = createGroup(RandomStringUtils.random(1), "Test Group"); // name is too short
		
		// mock (PostPutRequest)
		PostPutRequest<Group> postRequest = (PostPutRequest<Group>)mock(PostPutRequest.class);
		doReturn(group).when(postRequest).getParam();
		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(group).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(groupId).when(groupDao).update(group);

		// test
		try {
			createGroupResourceMock(groupDao).updateObject(authUser, groupId.getId(), postRequest, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
		}

		verify(groupDao, never()).findGroupById(any(Long.class));
		verify(groupDao, never()).update(any(Group.class));
	}

	/**
	 * Group name is too long, 400 HTTP_BAD_REQUEST response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testUpdateObject_ERR_WhenNameIsTooLong() throws Exception {

		// data
		TCID groupId = new TCID(123);
		Group group = createGroup(RandomStringUtils.random(100), "Test Group"); // name is too long
		
		// mock (PostPutRequest)
		PostPutRequest<Group> postRequest = (PostPutRequest<Group>)mock(PostPutRequest.class);
		doReturn(group).when(postRequest).getParam();
		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(group).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(groupId).when(groupDao).update(group);

		// test
		try {
			createGroupResourceMock(groupDao).updateObject(authUser, groupId.getId(), postRequest, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
		}

		verify(groupDao, never()).findGroupById(any(Long.class));
		verify(groupDao, never()).update(any(Group.class));
	}

	/**
	 * Group description is too long, 400 HTTP_BAD_REQUEST response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testUpdateObject_ERR_WhenDescriptionIsTooLong() throws Exception {

		// data
		TCID groupId = new TCID(123);
		Group group = createGroup("TestGroup", RandomStringUtils.random(1000)); // description is too long
		
		// mock (PostPutRequest)
		PostPutRequest<Group> postRequest = (PostPutRequest<Group>)mock(PostPutRequest.class);
		doReturn(group).when(postRequest).getParam();
		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(group).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(groupId).when(groupDao).update(group);

		// test
		try {
			createGroupResourceMock(groupDao).updateObject(authUser, groupId.getId(), postRequest, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
		}

		verify(groupDao, never()).findGroupById(any(Long.class));
		verify(groupDao, never()).update(any(Group.class));
	}

	/**
	 * Group name already exists, 400 HTTP_BAD_REQUEST response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testUpdateObject_ERR_WhenGroupNameAlreadyExists() throws Exception {
		// data
		TCID groupId = new TCID(123);
		Group group = createGroup("TestGroup", "Test Group");
		Group existingGroup = createGroup(groupId, "OldTestGroup", "Test Group", new TCID(111), DateTime.now(), null, null);
		
		// mock (PostPutRequest)
		PostPutRequest<Group> postRequest = (PostPutRequest<Group>)mock(PostPutRequest.class);
		doReturn(group).when(postRequest).getParam();
		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(existingGroup).when(groupDao).findGroupById(Utils.toLongValue(groupId));
		doReturn(groupId).when(groupDao).update(group);
		doReturn(true).when(groupDao).groupExists(group.getName());
		
		// test
		try {
			createGroupResourceMock(groupDao).updateObject(authUser, groupId.getId(), postRequest, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
		}

		verify(groupDao).findGroupById(Utils.toLongValue(groupId));
		verify(groupDao).groupExists(group.getName());
		verify(groupDao, never()).update(any(Group.class));
	}

	/**
	 * Group does not exist, 404 HTTP_NOT_FOUND response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testUpdateObject_ERR_WhenGroupDoesNotExists() throws Exception {
		// data
		TCID groupId = new TCID(123);
		Group group = createGroup("TestGroup", "Test Group");
		
		// mock (PostPutRequest)
		PostPutRequest<Group> postRequest = (PostPutRequest<Group>)mock(PostPutRequest.class);
		doReturn(group).when(postRequest).getParam();
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
			createGroupResourceMock(groupDao).updateObject(authUser, groupId.getId(), postRequest, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_NOT_FOUND, e.getHttpStatus());
		}

		verify(groupDao).findGroupById(Utils.toLongValue(groupId));
		verify(groupDao, never()).update(any(Group.class));
	}
}
