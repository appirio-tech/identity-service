package com.appirio.tech.core.service.identity.resource;

import static java.net.HttpURLConnection.HTTP_OK;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.request.PostPutRequest;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.dao.GroupDAO;
import com.appirio.tech.core.service.identity.dao.GroupInformixDAO;
import com.appirio.tech.core.service.identity.representation.Group;
import com.appirio.tech.core.service.identity.representation.GroupMembership;
import com.appirio.tech.core.service.identity.representation.SecurityGroup;

/**
 * GroupResource_EnhancementTest is used to test the group apis add in 72h TC Identity Service API Enhancements v1.0
 * 
 * It's added in 72h TC Identity Service API Enhancements v1.0
 * 
 * @author TCCoder
 * @version 1.0
 *
 */
public class GroupResource_EnhancementTest extends GroupResourceTestBase {
    
    /**
     * Test get member count
     *
     * @throws Exception if any error occurs
     */
    @Test
    public void testGetMemberCount() throws Exception {
        Group group = createGroup("TestGroup", "Test Group");
        // data
        TCID groupId = new TCID(123);

        group.setId(groupId);
        List<Long> groupIds = new ArrayList<Long>() {
            {
                add(123L);
            }
        };
        TCID userId = new TCID(123456789L);
        // mock (GroupDAO)
        GroupDAO groupDao = mock(GroupDAO.class);
        when(groupDao.getMemberCount(groupIds, 1)).thenReturn(2);
        
        when(groupDao.findGroupById(Long.valueOf(group.getId().getId()))).thenReturn(group);
        //when(groupDao.findSubGroups(1)).thenReturn(null);
       
        // testee
        GroupResource testee = createGroupResourceMock(groupDao);

        // test
        ApiResponse result = testee.getMembersCount(groupId, true);

        // checking result
        checkApiResponseHeader(result, HTTP_OK);

        TCID id = (TCID) result.getResult().getContent();
        assertEquals(id.getId(), "2");
        verify(groupDao).getMemberCount(groupIds, 1);
    }
    
    /**
     * Test create security groups
     *
     * @throws Exception if any error occurs
     */
    @Test
    public void testCreateSecurityGroups() throws Exception {
        SecurityGroup group = new SecurityGroup();

        group.setName("name");
        group.setId(123);
        // mock (AuthUser)
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        // mock (GroupDAO)
        GroupDAO groupDao = mock(GroupDAO.class);

       
        //when(groupDao.findSubGroups(1)).thenReturn(null);
       
        GroupInformixDAO groupInformixDao = mock(GroupInformixDAO.class);
        when(groupInformixDao.findGroupById(group.getId())).thenReturn(null);
        when(groupInformixDao.findGroupByName(group.getName())).thenReturn(null);
        when(groupInformixDao.createGroup(group)).thenReturn(1);
        
        // testee
        GroupResource testee = spy(new GroupResource(groupDao, groupInformixDao));

        PostPutRequest<SecurityGroup> param = (PostPutRequest<SecurityGroup>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(group);
        
        // test
        ApiResponse result = testee.createSecurityGroup(authUser, param);

        // checking result
        checkApiResponseHeader(result, HTTP_OK);

        SecurityGroup res = (SecurityGroup) result.getResult().getContent();
        assertEquals(res.getId(), group.getId());

        verify(groupInformixDao).createGroup(group);
    }
    
    /**
     * Test get single membership
     *
     * @throws Exception if any error occurs
     */
    @Test
    public void testGetSingleMembership() throws Exception {
        Group group = createGroup("TestGroup", "Test Group");
        // data
        TCID groupId = new TCID(123);
        group.setId(groupId);
        
        GroupMembership memShip = new GroupMembership();
        memShip.setId(new TCID(1));

        // mock (AuthUser)
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        // mock (GroupDAO)
        GroupDAO groupDao = mock(GroupDAO.class);
        
        when(groupDao.findGroupById(Long.valueOf(group.getId().getId()))).thenReturn(group);
        when(groupDao.findMembershipByGroupAndMember(123L, 1L)).thenReturn(memShip);
        
        // testee
        GroupResource testee = spy(new GroupResource(groupDao, null));

        // test
        ApiResponse result = testee.getSingleMember(authUser, groupId, new TCID(1));

        // checking result
        checkApiResponseHeader(result, HTTP_OK);

        GroupMembership res = (GroupMembership) result.getResult().getContent();
        assertEquals(res.getId(), memShip.getId());

        verify(groupDao).findMembershipByGroupAndMember(123, 1);
    }

}
