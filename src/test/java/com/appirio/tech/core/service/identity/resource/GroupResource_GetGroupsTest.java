package com.appirio.tech.core.service.identity.resource;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;
import static java.net.HttpURLConnection.*;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.dao.GroupDAO;
import com.appirio.tech.core.service.identity.representation.Group;
import com.appirio.tech.core.service.identity.representation.GroupMembership.MembershipType;

@SuppressWarnings("unchecked")
public class GroupResource_GetGroupsTest extends GroupResourceTestBase {

	@Test
	public void testGetObjects_OK_FetchGroupsSpecifiedMemberBelongsTo() throws Exception {
		// data
		List<Group> groups = createSimpleGroups(3);
		
		long memberId = 12345L;
		MembershipType membershipType = MembershipType.User;
		
		// mock
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(groups).when(groupDao).findGroupsByMember(memberId, membershipType);
		
		HttpServletRequest request = mock(HttpServletRequest.class);
		
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		
		// testee
		GroupResource testee = createGroupResourceMock(groupDao);
		
		// test
		ApiResponse result = testee.getObjects(authUser, new TCID(memberId), membershipType.lowerName(), request);
		
		// checking result
		checkApiResponseHeader(result, HTTP_OK);
		
		List<Group> contents = (List<Group>)result.getResult().getContent();
		assertNotNull("Contents in the result should not be null.", contents);
		assertEquals(groups.size(), contents.size());
		for(int i=0; i<contents.size(); i++) {
			Group act = contents.get(i);
			Group exp = groups.get(i);
			assertEquals(exp.getName(), act.getName());
		}
		
		verify(groupDao).findGroupsByMember(memberId, membershipType);
	}
	
	@Test
	public void testGetObjects_OK_FetchGroupsByAdminUser() throws Exception {
		// data
		List<Group> groups = createSimpleGroups(3);
				
		// mock
		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(groups).when(groupDao).findAllGroups();
		
		HttpServletRequest request = mock(HttpServletRequest.class);
		
		TCID userId = new TCID(123456789L);
		AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
		
		// testee
		GroupResource testee = createGroupResourceMock(groupDao);
		
		// test
		ApiResponse result = testee.getObjects(authUser, null, null, request);
		
		// checking result
		checkApiResponseHeader(result, HTTP_OK);
		
		List<Group> contents = (List<Group>)result.getResult().getContent();
		assertNotNull("Contents in the result should not be null.", contents);
		assertEquals(groups.size(), contents.size());
		for(int i=0; i<contents.size(); i++) {
			Group act = contents.get(i);
			Group exp = groups.get(i);
			assertEquals(exp.getName(), act.getName());
		}
		
		verify(groupDao).findAllGroups();	
	}
	
	@Test
	public void testGetObjects_OK_FetchGroupsUserBelongsTo() throws Exception {
		// data
		List<Group> groups = createSimpleGroups(3);
		
		// mock
		long userId = 123456789L;
		AuthUser authUser = TestUtils.createNormalAuthUserMock(new TCID(userId));

		GroupDAO groupDao = mock(GroupDAO.class);
		doReturn(groups).when(groupDao).findGroupsByMember(userId, MembershipType.User);
		
		HttpServletRequest request = mock(HttpServletRequest.class);
		
		// testee
		GroupResource testee = createGroupResourceMock(groupDao);
		
		// test
		ApiResponse result = testee.getObjects(authUser, null, null, request);
		
		// checking result
		checkApiResponseHeader(result, HTTP_OK);
		
		List<Group> contents = (List<Group>)result.getResult().getContent();
		assertNotNull("Contents in the result should not be null.", contents);
		assertEquals(groups.size(), contents.size());
		for(int i=0; i<contents.size(); i++) {
			Group act = contents.get(i);
			Group exp = groups.get(i);
			assertEquals(exp.getName(), act.getName());
		}
		
		verify(groupDao).findGroupsByMember(userId, MembershipType.User);
	}
	
	@Test
	public void testGetObjects_ERR_WhenEitherMemberOrTypeIsNull() throws Exception {
		// membershipType is null
		testGetObjects_ERR_WhenEitherMemberOrTypeIsNull(new TCID(56789L), null);
		// memberId is null
		testGetObjects_ERR_WhenEitherMemberOrTypeIsNull(null, MembershipType.User.lowerName());		
	}
	
	public void testGetObjects_ERR_WhenEitherMemberOrTypeIsNull(TCID memberId, String membershipType) throws Exception {

		assertTrue(memberId==null || membershipType==null);
		
		// mock
		long userId = 123456789L;
		AuthUser authUser = TestUtils.createAdminAuthUserMock(new TCID(userId));
		GroupDAO groupDao = mock(GroupDAO.class);
		HttpServletRequest request = mock(HttpServletRequest.class);
		
		// testee
		GroupResource testee = createGroupResourceMock(groupDao);

		// test
		try {
			testee.getObjects(authUser, memberId, membershipType, request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
		}
	}
	
	@Test
	public void testGetObjects_ERR_WhenMembershipTypeIsInvalid() throws Exception {
	
		// mock
		AuthUser authUser = TestUtils.createAdminAuthUserMock(new TCID(123456789L));
		GroupDAO groupDao = mock(GroupDAO.class);
		HttpServletRequest request = mock(HttpServletRequest.class);
		
		// testee
		GroupResource testee = createGroupResourceMock(groupDao);

		// test
		try {
			testee.getObjects(authUser, new TCID(12345L), "unsupported", request);
			failWhenExpectedExceptionNotThrown();
		} catch (APIRuntimeException e) {
			assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
		}
	}
}
