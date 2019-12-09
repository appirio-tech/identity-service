/**
 * Copyright (C) 2017 Topcoder Inc., All Rights Reserved.
 */
package com.appirio.tech.core.service.identity.resource;

import static java.net.HttpURLConnection.HTTP_BAD_REQUEST;
import static java.net.HttpURLConnection.HTTP_NOT_FOUND;
import static java.net.HttpURLConnection.HTTP_OK;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.ArrayList;
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
import com.appirio.tech.core.service.identity.util.Utils;

/**
 * Unit tests for {@link GroupResource#getGroup(@Auth AuthUser authUser, @PathParam("groupId") TCID groupId, 
 * @QueryParam("includeSubGroups") boolean includeSubGroups, @QueryParam("oneLevel") boolean oneLevel)}.
 *
 * @author TCSCODER
 * @version 1.0
 */
public class GroupResource_GetSubGroupsTest extends GroupResourceTestBase {

    /**
     * Group should be retrieved properly.
     * 
     * @throws Exception to JUnit
     */
    @Test
    public void testGetGroup_OK_include_all_subGroups() throws Exception {
        // data
        TCID groupId = new TCID(123);
        Group existingGroup = createGroup(groupId, "TestGroup", "Test Group", new TCID(111), DateTime.now(),
                new TCID(222), DateTime.now());

        Group sub1 = createGroup(new TCID(2), "sub 1", "sub1", new TCID(111), DateTime.now(), new TCID(222),
                DateTime.now());
        Group sub2 = createGroup(new TCID(3), "sub 2", "sub2", new TCID(111), DateTime.now(), new TCID(222),
                DateTime.now());

        Group sub3 = createGroup(new TCID(4), "sub 3", "sub3", new TCID(111), DateTime.now(), new TCID(222),
                DateTime.now());

        List<Group> subGroups = new ArrayList<Group>(2) {
            {
                add(sub1);
                add(sub2);
            }
        };

        List<Group> subGroups2 = new ArrayList<Group>(1) {
            {
                add(sub3);
            }
        };

        // mock (HttpServletRequest)
        HttpServletRequest request = mock(HttpServletRequest.class);
        // mock (AuthUser)
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        // mock (GroupDAO)
        GroupDAO groupDao = mock(GroupDAO.class);
        doReturn(existingGroup).when(groupDao).findGroupById(Utils.toLongValue(groupId));
        doReturn(subGroups).when(groupDao).findSubGroups(Utils.toLongValue(groupId));
        doReturn(subGroups2).when(groupDao).findSubGroups(2L);

        // testee
        GroupResource testee = createGroupResourceMock(groupDao);

        // test
        ApiResponse result = testee.getGroup(authUser, groupId, null, true, false);

        // checking result
        checkApiResponseHeader(result, HTTP_OK);

        Group content = (Group) result.getResult().getContent();
        assertNotNull("A content in the result should not be null.", content);
        assertEquals(existingGroup.getId().getId(), content.getId().getId());
        assertEquals(existingGroup.getName(), content.getName());
        assertEquals(existingGroup.getDescription(), content.getDescription());
        assertEquals(existingGroup.getCreatedBy(), content.getCreatedBy());
        assertEquals(existingGroup.getCreatedAt(), content.getCreatedAt());
        assertEquals(existingGroup.getModifiedAt(), content.getModifiedAt());
        assertEquals(existingGroup.getModifiedBy(), content.getModifiedBy());

        assertNotNull("The sub groups should not be null", content.getSubGroups());

        assertEquals(content.getSubGroups().size(), 2);

        assertEquals(content.getSubGroups().get(0).getId(), new TCID(2));
        assertEquals(content.getSubGroups().get(1).getId(), new TCID(3));

        assertEquals(content.getSubGroups().get(0).getSubGroups().size(), 1);
        assertEquals(content.getSubGroups().get(0).getSubGroups().get(0).getId(), new TCID(4));

        assertNull("the subGroups should be null", content.getSubGroups().get(1).getSubGroups());
        verify(groupDao).findSubGroups(Utils.toLongValue(groupId));
    }

    /**
     * Group should be retrieved properly.
     * 
     * @throws Exception to JUnit
     */
    @Test
    public void testGetGroup_OK_oneLevel() throws Exception {
        // data
        TCID groupId = new TCID(123);
        Group existingGroup = createGroup(groupId, "TestGroup", "Test Group", new TCID(111), DateTime.now(),
                new TCID(222), DateTime.now());

        Group sub1 = createGroup(new TCID(2), "sub 1", "sub1", new TCID(111), DateTime.now(), new TCID(222),
                DateTime.now());
        Group sub2 = createGroup(new TCID(3), "sub 2", "sub2", new TCID(111), DateTime.now(), new TCID(222),
                DateTime.now());

        Group sub3 = createGroup(new TCID(4), "sub 3", "sub3", new TCID(111), DateTime.now(), new TCID(222),
                DateTime.now());

        List<Group> subGroups = new ArrayList<Group>(2) {
            {
                add(sub1);
                add(sub2);
            }
        };

        List<Group> subGroups2 = new ArrayList<Group>(1) {
            {
                add(sub3);
            }
        };

        // mock (AuthUser)
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        // mock (GroupDAO)
        GroupDAO groupDao = mock(GroupDAO.class);
        doReturn(existingGroup).when(groupDao).findGroupById(Utils.toLongValue(groupId));
        doReturn(subGroups).when(groupDao).findSubGroups(Utils.toLongValue(groupId));
        doReturn(subGroups2).when(groupDao).findSubGroups(2L);

        // testee
        GroupResource testee = createGroupResourceMock(groupDao);

        // test
        ApiResponse result = testee.getGroup(authUser, groupId, null, true, true);

        // checking result
        checkApiResponseHeader(result, HTTP_OK);

        Group content = (Group) result.getResult().getContent();
        assertNotNull("A content in the result should not be null.", content);
        assertEquals(existingGroup.getId().getId(), content.getId().getId());
        assertEquals(existingGroup.getName(), content.getName());
        assertEquals(existingGroup.getDescription(), content.getDescription());
        assertEquals(existingGroup.getCreatedBy(), content.getCreatedBy());
        assertEquals(existingGroup.getCreatedAt(), content.getCreatedAt());
        assertEquals(existingGroup.getModifiedAt(), content.getModifiedAt());
        assertEquals(existingGroup.getModifiedBy(), content.getModifiedBy());

        assertNotNull("The sub groups should not be null", content.getSubGroups());

        assertEquals(content.getSubGroups().size(), 2);

        assertEquals(content.getSubGroups().get(0).getId(), new TCID(2));
        assertEquals(content.getSubGroups().get(1).getId(), new TCID(3));

        assertNull("The sub groups should be null", content.getSubGroups().get(0).getSubGroups());

        assertNull("The sub groups should be null", content.getSubGroups().get(1).getSubGroups());
        verify(groupDao).findSubGroups(Utils.toLongValue(groupId));
    }

    /**
     * Group should be retrieved properly.
     * 
     * @throws Exception to JUnit
     */
    @Test
    public void testGetGroup_OK_excludeSubGroups() throws Exception {
        // data
        TCID groupId = new TCID(123);
        Group existingGroup = createGroup(groupId, "TestGroup", "Test Group", new TCID(111), DateTime.now(),
                new TCID(222), DateTime.now());

        Group sub1 = createGroup(new TCID(2), "sub 1", "sub1", new TCID(111), DateTime.now(), new TCID(222),
                DateTime.now());
        Group sub2 = createGroup(new TCID(3), "sub 2", "sub2", new TCID(111), DateTime.now(), new TCID(222),
                DateTime.now());

        Group sub3 = createGroup(new TCID(4), "sub 3", "sub3", new TCID(111), DateTime.now(), new TCID(222),
                DateTime.now());

        List<Group> subGroups = new ArrayList<Group>(2) {
            {
                add(sub1);
                add(sub2);
            }
        };

        List<Group> subGroups2 = new ArrayList<Group>(1) {
            {
                add(sub3);
            }
        };

        // mock (AuthUser)
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        // mock (GroupDAO)
        GroupDAO groupDao = mock(GroupDAO.class);
        doReturn(existingGroup).when(groupDao).findGroupById(Utils.toLongValue(groupId));
        doReturn(subGroups).when(groupDao).findSubGroups(Utils.toLongValue(groupId));
        doReturn(subGroups2).when(groupDao).findSubGroups(2L);

        // testee
        GroupResource testee = createGroupResourceMock(groupDao);

        // test
        ApiResponse result = testee.getGroup(authUser, groupId, null, false, true);

        // checking result
        checkApiResponseHeader(result, HTTP_OK);

        Group content = (Group) result.getResult().getContent();
        assertNotNull("A content in the result should not be null.", content);
        assertEquals(existingGroup.getId().getId(), content.getId().getId());
        assertEquals(existingGroup.getName(), content.getName());
        assertEquals(existingGroup.getDescription(), content.getDescription());
        assertEquals(existingGroup.getCreatedBy(), content.getCreatedBy());
        assertEquals(existingGroup.getCreatedAt(), content.getCreatedAt());
        assertEquals(existingGroup.getModifiedAt(), content.getModifiedAt());
        assertEquals(existingGroup.getModifiedBy(), content.getModifiedBy());

        assertNull("The sub groups should  be null", content.getSubGroups());

        verify(groupDao).findGroupById(Utils.toLongValue(groupId));
    }

    /**
     * Group id is invalid, 400 HTTP_BAD_REQUEST response should be returned.
     * 
     * @throws Exception to JUnit
     */
    @Test
    public void testGetObject_ERR_WhenGroupIdInvalid() throws Exception {
        // mock (AuthUser)
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        // mock (GroupDAO)
        GroupDAO groupDao = mock(GroupDAO.class);

        // test
        try {
            createGroupResourceMock(groupDao).getGroup(authUser, new TCID("invalid"), null, true, true);
            failWhenExpectedExceptionNotThrown();
        } catch (APIRuntimeException e) {
            assertEquals(HTTP_BAD_REQUEST, e.getHttpStatus());
        }

        verify(groupDao, never()).findGroupById(any(Long.class));
    }

    /**
     * Group does not exist, 404 HTTP_NOT_FOUND response should be returned.
     * 
     * @throws Exception to JUnit
     */
    @Test
    public void testGetObject_ERR_WhenGroupDoesNotExists() throws Exception {
        // data
        TCID groupId = new TCID(123);
        
        // mock (AuthUser)
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        // mock (GroupDAO)
        GroupDAO groupDao = mock(GroupDAO.class);
        doReturn(null).when(groupDao).findGroupById(Utils.toLongValue(groupId));

        // test
        try {
            createGroupResourceMock(groupDao).getGroup(authUser, groupId, null, true, true);
            failWhenExpectedExceptionNotThrown();
        } catch (APIRuntimeException e) {
            assertEquals(HTTP_NOT_FOUND, e.getHttpStatus());
        }

        verify(groupDao).findGroupById(Utils.toLongValue(groupId));
    }
}
