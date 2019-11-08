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
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import javax.servlet.http.HttpServletRequest;

import org.joda.time.DateTime;
import org.junit.Test;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.dao.GroupDAO;
import com.appirio.tech.core.service.identity.representation.Group;
import com.appirio.tech.core.service.identity.util.Utils;

/**
 * Unit tests for {@link GroupResource#deleteObject(AuthUser, String, HttpServletRequest)}.
 *
 * @author TCSCODER
 * @version 1.0
 */
public class GroupResource_DeleteGroupTest extends GroupResourceTestBase {

	/**
	 * Group should be deleted properly.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testDeleteObject_OK() throws Exception {
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
		doNothing().when(groupDao).delete(groupId);
		
		// testee
		GroupResource testee = createGroupResourceMock(groupDao);
		
		// test
		ApiResponse result = testee.deleteObject(authUser, groupId.getId(), request);
		
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
		verify(groupDao).delete(groupId);
		verify(authUser, atLeastOnce()).getRoles();
	}

	/**
	 * User is not admin, 403 HTTP_FORBIDDEN response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testDeleteObject_ERR_WhenUserIsNotAdmin() throws Exception {

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);

		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);

		// test
		try {
			createGroupResourceMock(groupDao).deleteObject(authUser, "123", request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_FORBIDDEN, e.getHttpStatus());
		}

		verify(groupDao, never()).findGroupById(any(Long.class));
		verify(groupDao, never()).delete(any(TCID.class));
	}

	/**
	 * Group id is invalid, 400 HTTP_BAD_REQUEST response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testDeleteObject_ERR_WhenGroupIdInvalid() throws Exception {

		// mock (HttpServletRequest)
		HttpServletRequest request = mock(HttpServletRequest.class);
		// mock (AuthUser)
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		// mock (GroupDAO)
		GroupDAO groupDao = mock(GroupDAO.class);
		
		// test
		try {
			createGroupResourceMock(groupDao).deleteObject(authUser, "invalid", request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
		}

		verify(groupDao, never()).findGroupById(any(Long.class));
		verify(groupDao, never()).delete(any(TCID.class));
	}

	/**
	 * Group does not exist, 404 HTTP_NOT_FOUND response should be returned.
	 * @throws Exception to JUnit
	 */
	@Test
	public void testDeleteObject_ERR_WhenGroupDoesNotExists() throws Exception {
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
			createGroupResourceMock(groupDao).deleteObject(authUser, groupId.getId(), request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_NOT_FOUND, e.getHttpStatus());
		}

		verify(groupDao).findGroupById(Utils.toLongValue(groupId));
		verify(groupDao, never()).delete(any(TCID.class));
	}
}
