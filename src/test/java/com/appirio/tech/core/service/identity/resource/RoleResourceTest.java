package com.appirio.tech.core.service.identity.resource;

import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static javax.servlet.http.HttpServletResponse.SC_NOT_FOUND;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;

import com.appirio.tech.core.api.v3.ApiVersion;
import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.dropwizard.APIApplication;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.request.FieldSelector;
import com.appirio.tech.core.api.v3.request.FilterParameter;
import com.appirio.tech.core.api.v3.request.PostPutRequest;
import com.appirio.tech.core.api.v3.request.QueryParameter;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.api.v3.response.Result;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.dao.RoleDAO;
import com.appirio.tech.core.service.identity.representation.Role;
import com.appirio.tech.core.service.identity.util.Utils;

import io.dropwizard.jackson.Jackson;

/**
 * Unit tests for {@link RoleResource}.
 * 
 * <p>
 * Version 1.2 - ROLES MANAGEMENT API ENHANCEMENTS
 * - Added unit tests for updateObject() and deleteObject().
 * - Added more tests for getObject() and getObjects().
 * - Change mock auth user.
 * </p>
 *
 * @author ramakrishnapemmaraju, TCSCODER
 * @version 1.2
 */
public class RoleResourceTest {

    public static final String ROLENAME = "testRole";
    public static final String ANOTHERROLENAME = "testRole1";
    public static final Long SUBJECTID = 1L;
    public static final Long ROLEID = 1L;
    public static final Long ANOTHERROLEID = 2L;
    public static final Long ID1 = 1L;
    public static final Long INVALIDID = 9999L;

    private List<Role> buildRoles() {
        Role role1 = new Role();
        role1.setRoleName(ROLENAME);
        role1.setId(new TCID(ROLEID));
        Role role2 = new Role();
        role2.setRoleName(ANOTHERROLENAME);
        role2.setId(new TCID(ANOTHERROLEID));

        List<Role> roles = new ArrayList<>();
        roles.add(role1);
        roles.add(role2);
        return roles;
    }

    private Role buildRole() {
        Role role = new Role();
        role.setRoleName(ROLENAME);
        return role;
    }
    
    /**
     * Get roles successfully.
     * @throws Exception to JUnit
     */
    @Test
    public void testGetObject() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        Role role = buildRole();

        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        FieldSelector selector = mock(FieldSelector.class);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.populateById(selector, roleId)).thenReturn(role);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        ApiResponse result = testee.getObject(authUser, roleId, selector, request);

        assertNotNull("getObject() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(role, apiResult.getContent());

        verify(roleDao).populateById(selector, roleId);
    }
    
    /**
     * Test get object for machine user
     *
     * @throws Exception if any error occurs
     */
    @Test
    public void testGetObject_machineUser() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        Role role = buildRole();

        TCID roleId = new TCID(ID1);
        AuthUser authUser = spy(new AuthUser());
        doReturn(true).when(authUser).isMachine();
        List<String> scope = new ArrayList<String>();
        scope.add("read:roles");
        doReturn(scope).when(authUser).getScope();
        doReturn(Arrays.asList(new String[]{"machine"})).when(authUser).getRoles();
        
        FieldSelector selector = mock(FieldSelector.class);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.populateById(selector, roleId)).thenReturn(role);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        ApiResponse result = testee.getObject(authUser, roleId, selector, request);

        assertNotNull("getObject() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int)apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        assertEquals(role, apiResult.getContent());

        verify(roleDao).populateById(selector, roleId);
    }
    
    /**
     * Test get object for machine user
     *
     * @throws Exception if any error occurs
     */
    @Test
    public void testGetObject_machineUser_401Error() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        Role role = buildRole();

        TCID roleId = new TCID(ID1);
        AuthUser authUser = spy(new AuthUser());
        doReturn(true).when(authUser).isMachine();
        List<String> scope = new ArrayList<String>();
        scope.add("write:roles");
        doReturn(scope).when(authUser).getScope();
        doReturn(Arrays.asList(new String[]{"machine"})).when(authUser).getRoles();
        
        FieldSelector selector = mock(FieldSelector.class);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.populateById(selector, roleId)).thenReturn(role);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);
        try {
            testee.getObject(authUser, roleId, selector, request);
            fail("Should get 401 exception here");
        } catch (APIRuntimeException e) {
            assertEquals(SC_FORBIDDEN, e.getHttpStatus());
        }
    }

    /**
     * Role id is null, 400 response should be returned.
     * @throws Exception to JUnit
     */
    @Test
    public void testGetObject_400Error() throws Exception {
        TCID roleId = null;

        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        FieldSelector selector = mock(FieldSelector.class);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(false);

        try {
            RoleResource testee = new RoleResource();
            testee.setDao(roleDao);
            testee.getObject(authUser, roleId, selector, request);
            fail("getObject() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        }

        verify(roleDao, never()).populateById(selector, roleId);
    }

    /**
     * Role not found, 404 response should be returned.
     * @throws Exception to JUnit
     */
    @Test
    public void testGetObject_404Error() throws Exception {
        TCID userId = new TCID(INVALIDID);

        AuthUser authUser = TestUtils.createAdminAuthUserMock(new TCID(123456789L));
        FieldSelector selector = mock(FieldSelector.class);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(false);

        try {
            RoleResource testee = new RoleResource();
            testee.setDao(roleDao);
            testee.getObject(authUser, userId, selector, request);
            fail("getObject() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_NOT_FOUND, e.getHttpStatus());
        }

        verify(roleDao).populateById(selector, userId);
    }

    @Test
    public void testGetObjects() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        QueryParameter query = mock(QueryParameter.class);
        when(query.getSelector()).thenReturn(null);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.getAllRoles()).thenReturn(buildRoles());

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        ApiResponse result = testee.getObjects(authUser, query, request);

        assertNotNull("getObjects() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int) apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());

        verify(roleDao).getAllRoles();
        verify(authUser, atLeastOnce()).getRoles();
        verify(query).getSelector();
        verify(roleDao, never()).getRolesBySubjectId(anyLong());
    }

    @Test
    public void testGetObjects_User() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        TCID userId = new TCID(1L);
        AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);
        QueryParameter query = mock(QueryParameter.class);
        when(query.getSelector()).thenReturn(null);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(false);
        when(roleDao.getRolesBySubjectId(anyLong())).thenReturn(buildRoles());

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        ApiResponse result = testee.getObjects(authUser, query, request);

        assertNotNull("getObject() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int) apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());

        verify(roleDao).getRolesBySubjectId(1L);
        verify(authUser, atLeastOnce()).getRoles();
        verify(query).getSelector();
        verify(roleDao, never()).getAllRoles();
    }

    /**
     * If subject id is specified, it should return roles for this subject id.
     * @throws Exception to JUnit
     */
    @Test
    public void testGetObjects_BySubjectId() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        QueryParameter query = mock(QueryParameter.class);
        FilterParameter filter = new FilterParameter("subjectID=" + "2");
        when(query.getFilter()).thenReturn(filter);
        when(query.getSelector()).thenReturn(null);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.getRolesBySubjectId(anyLong())).thenReturn(buildRoles());

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        ApiResponse result = testee.getObjects(authUser, query, request);

        assertNotNull("getObject() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int) apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());

        verify(roleDao).getRolesBySubjectId(2L);
        verify(authUser, atLeastOnce()).getRoles();
        verify(query).getSelector();
        verify(roleDao, never()).getAllRoles();
    }

    @Test
    public void testCreateObject() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        Role role = buildRole();

        PostPutRequest<Role> param = (PostPutRequest<Role>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(role);
        TCID roleId = new TCID(ID1);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(roleId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.create(role, roleId)).thenReturn(role);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        ApiResponse result = testee.createObject(authUser, param, request);

        assertNotNull("createObject() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int) apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());

        verify(roleDao).create(role, roleId);
        verify(authUser, atLeastOnce()).getRoles();
        verify(param).getParam();
    }

    @Test
    public void testCreateObject_403Error() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        Role role = buildRole();

        PostPutRequest<Role> param = (PostPutRequest<Role>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(role);
        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(false);
        when(roleDao.create(role, roleId)).thenReturn(role);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.createObject(authUser, param, request);
            fail("createObject() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_FORBIDDEN, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(authUser, atLeastOnce()).getRoles();
        verify(param).getParam();
        verify(roleDao,never()).create(role, roleId);
    }

    /**
     * Update object successfully.
     * @throws Exception to JUnit
     */
    @Test
    public void testUpdateObject() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();
        Role role = buildRole();
        Role existingRole = buildRole();
        existingRole.setRoleName("ExistingRole");

        PostPutRequest<Role> param = (PostPutRequest<Role>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(role);
        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.update(role)).thenReturn(role.getCreatedBy());
        when(roleDao.findRoleById(Utils.toLongValue(roleId))).thenReturn(existingRole);
        when(roleDao.findRoleByName(role.getRoleName())).thenReturn(null);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        ApiResponse result = testee.updateObject(authUser, roleId.getId(), param, request);

        assertNotNull("updateObject() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int) apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());

        verify(roleDao).update(role);
        verify(roleDao).findRoleByName(role.getRoleName());
        verify(roleDao).findRoleById(Utils.toLongValue(roleId));
        verify(authUser, atLeastOnce()).getRoles();
        verify(param).getParam();
    }

    /**
     * Auth user is not admin, 403 response should be returned.
     * @throws Exception to JUnit
     */
    @Test
    public void testUpdateObject_403Error() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();
        Role role = buildRole();

        PostPutRequest<Role> param = (PostPutRequest<Role>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(role);
        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(false);
        when(roleDao.update(role)).thenReturn(role.getId());
        when(roleDao.findRoleById(Utils.toLongValue(roleId))).thenReturn(role);
        when(roleDao.findRoleByName(role.getRoleName())).thenReturn(null);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.updateObject(authUser, roleId.getId(), param, request);
            fail("updateObjects() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_FORBIDDEN, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(roleDao, never()).findRoleById(Utils.toLongValue(roleId));
        verify(roleDao, never()).findRoleByName(role.getRoleName());
        verify(roleDao, never()).update(role);
        verify(param, never()).getParam();
        verify(authUser, atLeastOnce()).getRoles();
    }
    
    /**
     * Request is null, 400 response should be returned.
     * @throws Exception to JUnit
     */
    @Test
    public void testUpdateObject_400Error_RequestIsNull() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();
        Role role = buildRole();

        PostPutRequest<Role> param = (PostPutRequest<Role>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(role);
        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.update(role)).thenReturn(role.getId());
        when(roleDao.findRoleById(Utils.toLongValue(roleId))).thenReturn(role);
        when(roleDao.findRoleByName(role.getRoleName())).thenReturn(null);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.updateObject(authUser, roleId.getId(), null, request);
            fail("updateObjects() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(roleDao, never()).findRoleById(Utils.toLongValue(roleId));
        verify(roleDao, never()).findRoleByName(role.getRoleName());
        verify(roleDao, never()).update(role);
        verify(param, never()).getParam();
        verify(authUser, atLeastOnce()).getRoles();
    }
    
    /**
     * Role is null, 400 response should be returned.
     * @throws Exception to JUnit
     */
    @Test
    public void testUpdateObject_400Error_RoleIsNull() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();
        Role role = buildRole();

        PostPutRequest<Role> param = (PostPutRequest<Role>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(null);
        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.update(role)).thenReturn(role.getId());
        when(roleDao.findRoleById(Utils.toLongValue(roleId))).thenReturn(role);
        when(roleDao.findRoleByName(role.getRoleName())).thenReturn(null);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.updateObject(authUser, roleId.getId(), param, request);
            fail("updateObjects() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(roleDao, never()).findRoleById(Utils.toLongValue(roleId));
        verify(roleDao, never()).findRoleByName(role.getRoleName());
        verify(roleDao, never()).update(role);
        verify(param).getParam();
        verify(authUser, atLeastOnce()).getRoles();
    }
    
    /**
     * Role name is empty, 400 response should be returned.
     * @throws Exception to JUnit
     */
    @Test
    public void testUpdateObject_400Error_RoleNameIsEmpty() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();
        Role role = buildRole();
        role.setRoleName("");

        PostPutRequest<Role> param = (PostPutRequest<Role>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(role);
        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.update(role)).thenReturn(role.getId());
        when(roleDao.findRoleById(Utils.toLongValue(roleId))).thenReturn(role);
        when(roleDao.findRoleByName(role.getRoleName())).thenReturn(null);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.updateObject(authUser, roleId.getId(), param, request);
            fail("updateObjects() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(roleDao, never()).findRoleById(Utils.toLongValue(roleId));
        verify(roleDao, never()).findRoleByName(role.getRoleName());
        verify(roleDao, never()).update(role);
        verify(param).getParam();
        verify(authUser, atLeastOnce()).getRoles();
    }
    
    /**
     * Role id is invalid, 400 response should be returned.
     * @throws Exception to JUnit
     */
    @Test
    public void testUpdateObject_400Error_RoleIdIsInvalid() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();
        Role role = buildRole();
        TCID roleId = new TCID("invalid");
        role.setId(roleId);

        PostPutRequest<Role> param = (PostPutRequest<Role>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(role);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.update(role)).thenReturn(role.getId());
        when(roleDao.findRoleByName(role.getRoleName())).thenReturn(null);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.updateObject(authUser, roleId.getId(), param, request);
            fail("updateObjects() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(roleDao, never()).findRoleByName(role.getRoleName());
        verify(roleDao, never()).update(role);
        verify(param).getParam();
        verify(authUser, atLeastOnce()).getRoles();
    }
    
    /**
     * Role not found, 404 response should be returned.
     * @throws Exception to JUnit
     */
    @Test
    public void testUpdateObject_404Error() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();
        Role role = buildRole();

        PostPutRequest<Role> param = (PostPutRequest<Role>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(role);
        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.update(role)).thenReturn(role.getId());
        when(roleDao.findRoleById(Utils.toLongValue(roleId))).thenReturn(null);
        when(roleDao.findRoleByName(role.getRoleName())).thenReturn(null);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.updateObject(authUser, roleId.getId(), param, request);
            fail("updateObjects() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_NOT_FOUND, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(roleDao, never()).update(role);
        verify(roleDao, never()).findRoleByName(role.getRoleName());
        verify(roleDao).findRoleById(Utils.toLongValue(roleId));
        verify(param).getParam();
        verify(authUser, atLeastOnce()).getRoles();
    }
    
    /**
     * Role name already exists, 400 response should be returned.
     * @throws Exception to JUnit
     */
    @Test
    public void testUpdateObject_400Error_RoleNameExists() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();
        Role role = buildRole();
        Role exstingRole = buildRole();
        exstingRole.setRoleName("exstingRole");

        PostPutRequest<Role> param = (PostPutRequest<Role>)mock(PostPutRequest.class);
        when(param.getParam()).thenReturn(role);
        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.update(role)).thenReturn(role.getId());
        when(roleDao.findRoleById(Utils.toLongValue(roleId))).thenReturn(exstingRole);
        when(roleDao.findRoleByName(role.getRoleName())).thenReturn(role);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.updateObject(authUser, roleId.getId(), param, request);
            fail("updateObjects() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(roleDao, never()).update(role);
        verify(roleDao).findRoleByName(role.getRoleName());
        verify(roleDao).findRoleById(Utils.toLongValue(roleId));
        verify(param).getParam();
        verify(authUser, atLeastOnce()).getRoles();
    }
    
    /**
     * Delete object successfully.
     * @throws Exception to JUnit
     */
    @Test
    public void testDeleteObject() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        Role role = buildRole();
        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.findRoleById(Utils.toLongValue(roleId))).thenReturn(role);
        when(roleDao.deleteRole(ROLEID.toString())).thenReturn(roleId);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        ApiResponse result = testee.deleteObject(authUser, ROLEID.toString(), request);

        assertNotNull("deleteObject() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int) apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());

        verify(roleDao).deleteRole(ROLEID.toString());
        verify(roleDao).findRoleById(Utils.toLongValue(roleId));
        verify(authUser, atLeastOnce()).getRoles();
    }
    
    /**
     * Auth user is not admin, 403 response should be returned.
     * @throws Exception to JUnit
     */
    @Test
    public void testDeleteObject_403Error() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(false);
        when(roleDao.deleteRole(ROLENAME)).thenReturn(roleId);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.deleteObject(authUser, ROLENAME, request);
            fail("deleteObject() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_FORBIDDEN, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(authUser, atLeastOnce()).getRoles();
        verify(roleDao, never()).deleteRole(ROLENAME);
    }
    
    /**
     * Role id is null, 400 response should be returned.
     * @throws Exception to JUnit
     */
    @Test
    public void testDeleteObject_400Error() {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        String roleId = null;
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.deleteRole(roleId)).thenReturn(new TCID(ID1));

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.deleteObject(authUser, roleId, request);
            fail("deleteObject() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(authUser, atLeastOnce()).getRoles();
        verify(roleDao, never()).deleteRole(roleId);
    }
    
    /**
     * Role not found, 404 response should be returned.
     * @throws Exception to JUnit
     */
    @Test
    public void testDeleteObject_404Error() {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.findRoleById(Utils.toLongValue(roleId))).thenReturn(null);
        when(roleDao.deleteRole(roleId.getId())).thenReturn(new TCID(ID1));

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.deleteObject(authUser, roleId.getId(), request);
            fail("deleteObject() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_NOT_FOUND, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(roleDao).findRoleById(Utils.toLongValue(roleId));
        verify(authUser, atLeastOnce()).getRoles();
        verify(roleDao, never()).deleteRole(roleId.getId());
    }
    
    /**
     * Get roles successfully.
     * @throws Exception to JUnit
     */
    @Test
    public void testGetSubjects() throws Exception{
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        Role role = buildRole();

        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);
        FieldSelector selector = new FieldSelector();
        selector.addField("subjects");

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.getSubjects(roleId)).thenReturn(role);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        ApiResponse result = testee.getObject(authUser, roleId, selector, request);

        assertNotNull("getSubjects() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int) apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());

        verify(roleDao).getSubjects(roleId);
    }
    
    /**
     * Role not found, 404 response should be returned.
     * @throws Exception to JUnit
     */
    @Test
    public void testGetSubjects_404Error(){
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();
        
        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);
        FieldSelector selector = new FieldSelector();
        selector.addField("subjects");

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.getSubjects(roleId)).thenReturn(null);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.getObject(authUser, roleId, selector, request);
            fail("getSubjects() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_NOT_FOUND, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(roleDao).getSubjects(roleId);
    }
    
    /**
     * Role id is null, 400 response should be returned.
     * @throws Exception to JUnit
     */
    @Test
    public void testGetSubjects_400Error(){
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        TCID roleId = null;
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);
        FieldSelector selector = new FieldSelector();
        selector.addField("subjects");

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.getObject(authUser, roleId, selector, request);
            fail("getSubjects() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(roleDao, never()).getSubjects(roleId);
    }

    @Test
    public void testAssignRole() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        FilterParameter filter = new FilterParameter("subjectID=" + SUBJECTID.toString());
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        TCID roleId = new TCID(ID1);
        TCID operatorId = new TCID(SUBJECTID);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.assign(roleId, new TCID(SUBJECTID), operatorId)).thenReturn(new TCID(ID1));

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        ApiResponse result = testee.assignRole(authUser, roleId, query, request);

        assertNotNull("assignRole() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int) apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());

        verify(authUser, atLeastOnce()).getRoles();
        verify(query).getFilter();
    }

    @Test
    public void testAssignRole_403Error() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        FilterParameter filter = new FilterParameter("subjectID=" + SUBJECTID.toString());
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        TCID roleId = new TCID(ID1);
        TCID operatorId = new TCID(SUBJECTID);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(false);
        when(roleDao.assign(roleId, new TCID(SUBJECTID), operatorId)).thenReturn(new TCID(ID1));

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.assignRole(authUser, roleId, query, request);
            fail("assignRole() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_FORBIDDEN, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(authUser, atLeastOnce()).getRoles();
        verify(query, never()).getFilter();
        verify(roleDao, never()).assign(roleId, new TCID(SUBJECTID.toString()), operatorId);
    }

    @Test
    public void testAssignRole_400Error() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        FilterParameter filter = new FilterParameter("subjectID=" + SUBJECTID.toString());
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        TCID roleId = new TCID(ID1);
        TCID operatorId = new TCID(SUBJECTID);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.assign(roleId, new TCID(SUBJECTID), operatorId)).thenReturn(new TCID(ID1));

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.assignRole(authUser, null, query, request);
            fail("assignRole() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(query, never()).getFilter();
        verify(roleDao, never()).assign(roleId, new TCID(SUBJECTID.toString()), operatorId);
    }

    @Test
    public void testDeassignRole() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        FilterParameter filter = new FilterParameter("subjectID=" + SUBJECTID.toString());
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.deassign(roleId, new TCID(SUBJECTID))).thenReturn(new TCID(ID1));

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        ApiResponse result = testee.deassignRole(authUser, roleId, query, request);

        assertNotNull("deassignRole() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int) apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());

        verify(authUser, atLeastOnce()).getRoles();
        verify(query).getFilter();
    }

    @Test
    public void testDeassignRole_403Error() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        FilterParameter filter = new FilterParameter("subjectID=" + SUBJECTID.toString());
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createNormalAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(false);
        when(roleDao.deassign(roleId, new TCID(SUBJECTID))).thenReturn(new TCID(ID1));

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.deassignRole(authUser, roleId, query, request);
            fail("deassignRole() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_FORBIDDEN, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(authUser, atLeastOnce()).getRoles();
        verify(query, never()).getFilter();
        verify(roleDao, never()).deassign(roleId, new TCID(SUBJECTID.toString()));
    }

    @Test
    public void testDeassignRole_400Error() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        FilterParameter filter = new FilterParameter("subjectID=" + SUBJECTID.toString());
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);
        when(roleDao.deassign(roleId, new TCID(SUBJECTID))).thenReturn(new TCID(ID1));

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.deassignRole(authUser, null, query, request);
            fail("deassignRole() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(query, never()).getFilter();
        verify(roleDao, never()).deassign(roleId, new TCID(SUBJECTID.toString()));
    }

    @Test
    public void testHasRole() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        FilterParameter filter = new FilterParameter("subjectID=" + SUBJECTID.toString());
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        ApiResponse result = testee.hasRole(authUser, roleId, query, request);

        assertNotNull("hasRole() should not return null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int) apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());

        verify(roleDao).checkRole(anyString(), anyString());
        verify(query).getFilter();
    }

    @Test
    public void testHasRole_404Error() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        FilterParameter filter = new FilterParameter("subjectID=" + SUBJECTID.toString());
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        TCID roleId = new TCID(ID1);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(false);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.hasRole(authUser, roleId, query, request);
            fail("hasRole() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_NOT_FOUND, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(roleDao).checkRole(anyString(), anyString());
        verify(query).getFilter();
    }

    @Test
    public void testHasRole_400Error() throws Exception {
        APIApplication.JACKSON_OBJECT_MAPPER = Jackson.newObjectMapper();

        FilterParameter filter = new FilterParameter("subjectID=" + SUBJECTID.toString());
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        HttpServletRequest request = mock(HttpServletRequest.class);

        RoleDAO roleDao = mock(RoleDAO.class);
        when(roleDao.checkRole(anyString(), anyString())).thenReturn(true);

        RoleResource testee = new RoleResource();
        testee.setDao(roleDao);

        try {
            ApiResponse result = testee.hasRole(authUser, null, query, request);
            fail("hasRole() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        } catch (Exception e) {
            fail("Should not throw any other exception");
        }

        verify(roleDao, never()).checkRole(anyString(), anyString());
        verify(query, never()).getFilter();
    }
}
