/**
 * Copyright (C) 2017 Topcoder Inc., All Rights Reserved.
 */
package com.appirio.tech.core.service.identity.dao;

import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.service.identity.representation.Role;

/**
 * Unit tests for {@link RoleDAO}.
 * 
 * <p>
 * Version 1.2 - ROLES MANAGEMENT API ENHANCEMENTS
 * - Added unit tests for update().
 * </p>
 *
 * @author ramakrishnapemmaraju, TCSCODER
 * @version 1.2
 */
public class RoleDAOTest {

    public static final String ROLENAME = "testRole";
    public static final String ANOTHERROLENAME = "testRole1";
    public static final Long SUBJECTID = 1L;
    public static final Long ROLEID = 1L;
    public static final Long ANOTHERROLEID = 2L;
    public static final Long ID1 = 1L;
    public static final Long ID2 = 2L;
    public static final int RET = 1;


    private Role buildRole() {
        Role role = new Role();
        role.setRoleName(ROLENAME);
        return role;
    }

    private List<Role> buildRoles() {
        Role role1 = new Role();
        role1.setRoleName(ROLENAME);
        role1.setId(new TCID(ROLEID));
        Role role2 = new Role();
        role2.setRoleName(ANOTHERROLENAME);
        role2.setId(new TCID(ANOTHERROLEID));

        List<Role> roles = new ArrayList<Role>();
        roles.add(role1);
        roles.add(role2);
        return roles;
    }

    private List<TCID> buildTCIDs() {
        TCID id1 = new TCID(ID1);
        TCID id2 = new TCID(ID2);

        List<TCID> ids = new ArrayList<TCID>();
        ids.add(id1);
        ids.add(id2);
        return ids;
    }

    @Test
    public void testGetAllRoles() {
        RoleDAO dao = mock(RoleDAO.class);
        when(dao.getAllRoles()).thenReturn(buildRoles());

        List<Role> roles = dao.getAllRoles();
        Assert.assertNotNull(roles);
        Assert.assertFalse(roles.isEmpty());
    }

    @Test
    public void testGetRolesBySubjectId() {
        RoleDAO dao = mock(RoleDAO.class);
        when(dao.getRolesBySubjectId(anyLong())).thenReturn(buildRoles());

        List<Role> roles = dao.getRolesBySubjectId(SUBJECTID);
        Assert.assertNotNull(roles);
        Assert.assertFalse(roles.isEmpty());
    }

    @Test
    public void testFindRoleById() {
        RoleDAO dao = mock(RoleDAO.class);
        when(dao.findRoleById(anyLong())).thenReturn(buildRole());

        Role role = dao.findRoleById(ROLEID);
        Assert.assertNotNull(role);
    }

    @Test
    public void testFindRoleByName() {
        RoleDAO dao = mock(RoleDAO.class);
        when(dao.findRoleByName(anyString())).thenReturn(buildRole());

        Role role = dao.findRoleByName(ROLENAME);
        Assert.assertNotNull(role);
    }

    @Test
    public void testCreateNewRole() {

        try {
            RoleDAO dao = mock(RoleDAO.class);
            when(dao.createNewRole(anyString(), anyLong())).thenReturn(ROLEID);
            Long id = dao.createNewRole(ROLENAME, ROLEID);
            Assert.assertNotNull(id);
        } catch(Exception e) {
            Assert.fail("Should not throw exception");
        }
    }

    /**
     * Update success.
     */
    @Test
    public void testUpdateRole() {

        try {
            Role role = buildRole();
            Set<TCID> subjects = new HashSet<TCID>();
            subjects.add(new TCID(111));
            role.setSubjects(subjects);
            role.setModifiedBy(new TCID(1));
            role.setId(new TCID(1L));
            RoleDAO dao = mock(RoleDAO.class);
            when(dao.updateRole(role)).thenReturn(1L);
            when(dao.assignRole(1, 111, 1)).thenReturn(RET);
            when(dao.deleteRoleAssignmentsByRoleId("1")).thenReturn(RET);
            doCallRealMethod().when(dao).update(any(Role.class));
            TCID id = dao.update(role);
            Assert.assertNotNull(id);
            verify(dao).updateRole(role);
            verify(dao).assignRole(1, 111, 1);
            verify(dao).deleteRoleAssignmentsByRoleId("1");
        } catch(Exception e) {
            Assert.fail("Should not throw exception");
        }
    }

    /**
     * Update fail with IllegalArgumentException when role is null.
     */
    @Test
    public void testUpdateRole_RoleIsNull() {

        try {
            RoleDAO dao = mock(RoleDAO.class);
            doCallRealMethod().when(dao).update(any(Role.class));
            dao.update(null);
            fail("An exception should be thrown in the previous step.");
        } catch(IllegalArgumentException e) {
            
        } catch(Exception e) {
            Assert.fail("Should not throw other exceptions");
        }
    }

    /**
     * Update fail with IllegalArgumentException when role id is invalid.
     */
    @Test
    public void testUpdateRole_RoleIdIsInvalid() {

        try {
            Role role = buildRole();
            role.setId(new TCID("invalid"));
            RoleDAO dao = mock(RoleDAO.class);
            doCallRealMethod().when(dao).update(any(Role.class));
            dao.update(null);
            fail("An exception should be thrown in the previous step.");
        } catch(IllegalArgumentException e) {
            
        } catch(Exception e) {
            Assert.fail("Should not throw other exceptions");
        }
    }

    @Test
    public void testGetPerms() {
        RoleDAO dao = mock(RoleDAO.class);
        when(dao.getPerms(anyLong())).thenReturn(buildTCIDs());

        List<TCID> perms = dao.getPerms(ROLEID);
        Assert.assertNotNull(perms);
        Assert.assertFalse(perms.isEmpty());
    }

    @Test
    public void testGetSubs() {
        RoleDAO dao = mock(RoleDAO.class);
        when(dao.getSubs(anyLong())).thenReturn(buildTCIDs());

        List<TCID> subs = dao.getSubs(ROLEID);
        Assert.assertNotNull(subs);
        Assert.assertFalse(subs.isEmpty());
    }

    @Test
    public void testAssignRole() {
        RoleDAO dao = mock(RoleDAO.class);
        when(dao.assignRole(anyLong(), anyLong(), anyLong())).thenReturn(RET);

        int ret = dao.assignRole(ROLEID, SUBJECTID, SUBJECTID);
        Assert.assertNotNull(ret);
    }

    @Test
    public void testDeassignRole() {
        RoleDAO dao = mock(RoleDAO.class);
        when(dao.deassignRole(anyLong(), anyLong())).thenReturn(RET);

        int ret = dao.deassignRole(ROLEID, SUBJECTID);
        Assert.assertNotNull(ret);
    }

    @Test
    public void testDeleteRoleById() {
        RoleDAO dao = mock(RoleDAO.class);
        when(dao.deleteRoleById(anyString())).thenReturn(RET);

        int ret = dao.deleteRoleById(ROLENAME);
        Assert.assertNotNull(ret);
    }

    /**
     * Delete success.
     */
    @Test
    public void testDeleteRole() {

        try {
            RoleDAO dao = mock(RoleDAO.class);
            when(dao.deleteRoleById("1")).thenReturn(1);
            doCallRealMethod().when(dao).deleteRole(any(String.class));
            TCID id = dao.deleteRole("1");
            Assert.assertNotNull(id);
            verify(dao).deleteRoleById("1");
            verify(dao).deleteRoleAssignmentsByRoleId("1");
        } catch(Exception e) {
            Assert.fail("Should not throw exception");
        }
    }

    /**
     * Delete fail with IllegalArgumentException when id is null.
     */
    @Test
    public void testDeleteRole_IdIsNull() {

        try {
            RoleDAO dao = mock(RoleDAO.class);
            doCallRealMethod().when(dao).deleteRole(any(String.class));
            dao.deleteRole(null);
            fail("An exception should be thrown in the previous step.");
        } catch(IllegalArgumentException e) {
            
        } catch(Exception e) {
            Assert.fail("Should not throw other exceptions");
        }
    }

    /**
     * Delete fail with IllegalArgumentException when id is invalid.
     */
    @Test
    public void testDeleteRole_RoleIdIsInvalid() {

        try {
            Role role = buildRole();
            role.setId(new TCID("invalid"));
            RoleDAO dao = mock(RoleDAO.class);
            doCallRealMethod().when(dao).deleteRole(any(String.class));
            dao.deleteRole("invalid");
            fail("An exception should be thrown in the previous step.");
        } catch(IllegalArgumentException e) {
            
        } catch(Exception e) {
            Assert.fail("Should not throw other exceptions");
        }
    }

    @Test
    public void testGetSubjects() {
        RoleDAO dao = mock(RoleDAO.class);
        TCID roleId = mock(TCID.class);
        when(dao.getSubs(anyLong())).thenReturn(buildTCIDs());
        when(dao.getSubjects(roleId)).thenReturn(buildRole());

        Role role = dao.getSubjects(roleId);
        Assert.assertNotNull(role);
    }
}
