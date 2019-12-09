package com.appirio.tech.core.service.identity.resource;

import static java.net.HttpURLConnection.HTTP_BAD_REQUEST;
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

import org.junit.Test;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.request.PostPutRequest;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.dao.GroupDAO;
import com.appirio.tech.core.service.identity.representation.Group;

@SuppressWarnings("unchecked")
public class GroupResource_CreateGroupTest extends GroupResourceTestBase {

	@Test
	public void testCreateObject_OK() throws Exception {
		// data
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
		doReturn(false).when(groupDao).groupExists(group.getName());
		doReturn(group).when(groupDao).create(group);
		
		// testee
		GroupResource testee = createGroupResourceMock(groupDao);
		
		// test
		ApiResponse result = testee.createObject(authUser, postRequest, request);
		
		// checking result
		checkApiResponseHeader(result, HTTP_OK);
		
		Group content = (Group)result.getResult().getContent();		
		assertNotNull("A content in the result should not be null.", content);
		assertEquals(group.getName(), content.getName());
		assertEquals(group.getDescription(), content.getDescription());
		assertEquals(userId, content.getCreatedBy());
		assertNotNull(content.getCreatedAt());
		
		verify(postRequest).getParam();
		verify(groupDao).groupExists(group.getName());
		verify(groupDao).create(group);
		verify(authUser, atLeastOnce()).getUserId();
		verify(authUser, atLeastOnce()).getRoles();
	}
	
	@Test
	public void testCreateObject_ERR_WhenUserIsNotAdmin() throws Exception {

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
			createGroupResourceMock(groupDao).createObject(authUser, postRequest, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_FORBIDDEN, e.getHttpStatus());
		}
		
		verify(groupDao, never()).create(any(Group.class));
	}
	
	@Test
	public void testCreateObject_ERR_WhenParamIsInsufficient() throws Exception {

		// data
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
		doReturn(group).when(groupDao).create(group);

		// test
		try {
			createGroupResourceMock(groupDao).createObject(authUser, postRequest, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
		}
		
		verify(groupDao, never()).create(any(Group.class));
	}
	
	@Test
	public void testCreateObject_ERR_WhenGroupAlreadyExists() throws Exception {

		// data
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
		doReturn(true).when(groupDao).groupExists(group.getName());
		doReturn(group).when(groupDao).create(group);

		// test
		try {
			createGroupResourceMock(groupDao).createObject(authUser, postRequest, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
		}
		
		verify(groupDao).groupExists(group.getName());
		verify(groupDao, never()).create(any(Group.class));
	}
}
