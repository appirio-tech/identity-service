/**
 * Copyright (C) 2017 Topcoder Inc., All Rights Reserved.
 */
package com.appirio.tech.core.service.identity.resource;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.request.FieldSelector;
import com.appirio.tech.core.api.v3.request.FilterParameter;
import com.appirio.tech.core.api.v3.request.PostPutRequest;
import com.appirio.tech.core.api.v3.request.QueryParameter;
import com.appirio.tech.core.api.v3.request.annotation.APIFieldParam;
import com.appirio.tech.core.api.v3.request.annotation.APIQueryParam;
import com.appirio.tech.core.api.v3.resource.DDLResource;
import com.appirio.tech.core.api.v3.resource.GetResource;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.api.v3.response.ApiResponseFactory;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.clients.MemberApiClient;
import com.appirio.tech.core.service.identity.dao.RoleDAO;
import com.appirio.tech.core.service.identity.representation.MemberInfo;
import com.appirio.tech.core.service.identity.representation.Role;
import com.appirio.tech.core.service.identity.representation.RoleSubjects;
import com.appirio.tech.core.service.identity.util.Utils;
import com.codahale.metrics.annotation.Timed;
import io.dropwizard.auth.Auth;
import org.apache.log4j.Logger;
import org.joda.time.DateTime;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

import static com.appirio.tech.core.service.identity.util.Constants.MSG_TEMPLATE_DUPLICATED;
import static com.appirio.tech.core.service.identity.util.Constants.MSG_TEMPLATE_INVALID;
import static com.appirio.tech.core.service.identity.util.Constants.MSG_TEMPLATE_MANDATORY;
import static com.appirio.tech.core.service.identity.util.Constants.MSG_TEMPLATE_NOT_EXIST;
import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * API resource to manage roles.
 * 
 * <p>
 * Version 1.2 - ROLES MANAGEMENT API ENHANCEMENTS
 * - Added feature to get roles by subjectId in getObjects().
 * - Improved implementation of updateObject().
 * - Improved implementation of deleteObject().
 * - Fixed authorization.
 * 
 * </p>
 *
 * @author TCSCODER
 * @version 1.2
 */
@Path("roles")
@Produces(MediaType.APPLICATION_JSON)
public class RoleResource implements GetResource<Role>, DDLResource<Role>{

	private static final Logger logger = Logger.getLogger(RoleResource.class);

	protected RoleDAO dao;

	protected MemberApiClient memberApiClient;
	
	public RoleResource() {
	}

	public RoleResource(RoleDAO roleDao, MemberApiClient memberApiClient) {
		this.dao = roleDao;
		this.memberApiClient = memberApiClient;
	}
	public RoleDAO getDao() {
		return dao;
	}

	public void setDao(RoleDAO dao) {
		this.dao = dao;
	}

	public MemberApiClient getMemberApiClient() {
		return memberApiClient;
	}

	public void setMemberApiClient(MemberApiClient memberApiClient) {
		this.memberApiClient = memberApiClient;
	}

	/**
     * Get roles.
     * 
     * @param authUser the authenticated user
     * @param subjectId the subject id
     * @param query the query parameters.
     * @param request the http request
     * @return the api response
     * @throws APIRuntimeException if any error occurs
     * @since 1.1
     */
	@GET
	@Timed
	public ApiResponse getObjects(
			@Auth AuthUser authUser, 
			@APIQueryParam(repClass = Role.class)QueryParameter query,
			@Context HttpServletRequest request) throws Exception {
		logger.info(String.format("getObjects()"));

		List<Role> roles;
		boolean isAdminAccess = Utils.hasAdminRole(authUser);
		if (authUser.isMachine()) {
		    if (authUser.getScope() == null || !authUser.getScope().contains("read:roles")) {
			throw new APIRuntimeException(HttpServletResponse.SC_FORBIDDEN, "The machine user should have the scope as 'read:roles'");
		    } else {
			isAdminAccess = true;
		    }
		}

		TCID subjectId = null;
        FilterParameter filter = query.getFilter();
        if (filter != null && filter.get("subjectID") != null) {
            subjectId = new TCID((String) filter.get("subjectID"));
        }
        
        if (subjectId != null && !Utils.isValid(subjectId))
            throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_INVALID, "Subject id"));
        
		if (isAdminAccess && subjectId == null) {
			roles = dao.getAllRoles();
		} else {
    		if (!isAdminAccess) {
    		    if (subjectId != null && subjectId != authUser.getUserId()) {
    		        throw new APIRuntimeException(HttpServletResponse.SC_FORBIDDEN, "Forbidden");
    		    }
    		    subjectId = authUser.getUserId();
    		}

            if (!Utils.isValid(subjectId)) {
                throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_INVALID, "Subject id"));
            }
    		
    		roles = dao.getRolesBySubjectId(Utils.toLongValue(subjectId));
		}

		return ApiResponseFactory.createFieldSelectorResponse(roles, query.getSelector());
	}

    /**
     * Create a new role.
     * 
     * @param authUser the authenticated user
     * @param postRequest the post request
     * @param request the http request
     * @return the api response
     * @throws APIRuntimeException if any error occurs
     * @since 1.2
     */
	@Override
	@POST
	@Timed
	public ApiResponse createObject(
			@Auth AuthUser authUser,
			@Valid PostPutRequest<Role> postRequest,
			@Context HttpServletRequest request)
			throws Exception {

		logger.info(String.format("createObject()"));

		Role role = postRequest.getParam();
		TCID subjectId = authUser.getUserId();

        if (!Utils.hasAdminRole(authUser))
			throw new APIRuntimeException(HttpServletResponse.SC_FORBIDDEN);

		try {
			role = dao.create(role, subjectId);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
			throw e;
		}

		return ApiResponseFactory.createFieldSelectorResponse(role, null);
	}

    /**
     * Update roles.
     * 
     * @param authUser the authenticated user
     * @param roleId the role id
     * @param putRequest the put request.
     * @param request the http request
     * @return the api response
     * @throws APIRuntimeException if any error occurs
     * @since 1.2
     */
	@Override
	@PUT
    @Path("/{roleId}")
	@Timed
	public ApiResponse updateObject(
			@Auth AuthUser authUser,
			@PathParam("roleId") String roleId,
			@Valid PostPutRequest<Role> putRequest,
			@Context HttpServletRequest request)
			throws Exception {
		logger.info(String.format("updateObject(%s)", roleId));

		Role role = validateRole(authUser, putRequest);
		
		Role existingRole = getExistingRole(new TCID(roleId));

		if (!role.getRoleName().equals(existingRole.getRoleName())
				&& dao.findRoleByName(role.getRoleName()) != null) {
			// The name changes, check duplicate
			throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_DUPLICATED, role.getRoleName()));
		}
		
        role.setId(existingRole.getId());
        role.setCreatedAt(existingRole.getCreatedAt());
        role.setCreatedBy(existingRole.getCreatedBy());
        role.setModifiedBy(authUser.getUserId());
        role.setModifiedAt(DateTime.now());

		try {
			dao.update(role);
		} catch (Exception e) {
			logger.error("Failed to update role.", e);
            throw new APIRuntimeException(SC_INTERNAL_SERVER_ERROR, e);
		}

		return ApiResponseFactory.createFieldSelectorResponse(role, null);
	}

    /**
     * Get roles.
     * 
     * If selector has "subjects" field it will return all subjects in this role.
     * 
     * @param authUser the authenticated user
     * @param roleId the role id
     * @param selector the field selector.
     * @param request the http request
     * @return the api response
     * @throws APIRuntimeException if any error occurs
     * @since 1.2
     */
	@Override
	@GET
	@Path("/{roleId}")
	@Timed
	public ApiResponse getObject(
			@Auth AuthUser authUser,
			@PathParam("roleId") TCID roleId,
			@APIFieldParam(repClass = Role.class) FieldSelector selector,
			@Context HttpServletRequest request)
			throws Exception {
		logger.info(String.format("getObject() "));
        
        if (!Utils.isValid(roleId)) {
            throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_INVALID, "Role id"));
        }

        if (authUser.isMachine()) {
            if (authUser.getScope() == null || !authUser.getScope().contains("read:roles")) {
                throw new APIRuntimeException(HttpServletResponse.SC_FORBIDDEN, "The machine user should have the scope as 'read:roles'");
            }
        }
        
        Role role = null;
		RoleSubjects roleSubjects = null;
        try {
    		if (hasField(selector, "subjects")) {
    			logger.info("Found subjects");
    			role = dao.getSubjects(roleId);
				if (role != null) {
					roleSubjects = new RoleSubjects();
					roleSubjects.setRoleName(role.getRoleName());
					roleSubjects.setSubjects(new ArrayList<>());
					if (!role.getSubjects().isEmpty()) {
						int currentIndex=0;
						TCID[] subjects = role.getSubjects().toArray(new TCID[0]);
						// If we try to get _all_ member details at once, the member API may throw a 502 because the request is too big
						// So, we split it up into blocks of 40
						while(currentIndex<subjects.length) {
							ArrayList<TCID> currentRequest=new ArrayList<TCID>();
							for(int i=0; i<=40; i++){
								currentRequest.add(subjects[currentIndex]);
								currentIndex++;
								if(currentIndex>=subjects.length){
									break;
								}
							}

							List<MemberInfo> memberList = memberApiClient.getUserInfoList(currentRequest.toArray(new TCID[0]));
							Map<String, MemberInfo> infoMap = memberList.stream().collect(
									Collectors.toMap(m -> m.getUserId().toString(), model -> model));
							for (TCID userId: currentRequest) {
								MemberInfo info = new MemberInfo();
								info.setUserId(Long.parseLong(userId.getId()));
								if (infoMap.containsKey(userId.getId())) {
									MemberInfo realInfo = infoMap.get(userId.getId());
									info.setEmail(realInfo.getEmail());
									info.setHandle(realInfo.getHandle());
								}
								roleSubjects.getSubjects().add(info);
							}
						}
					}
				}
    		} else {
    			role = dao.populateById(selector, roleId);
    		}
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new APIRuntimeException(SC_INTERNAL_SERVER_ERROR, e);
        }
        
        if (role == null)
            throw new APIRuntimeException(HttpServletResponse.SC_NOT_FOUND);

		if (roleSubjects != null) {
			return ApiResponseFactory.createFieldSelectorResponse(roleSubjects, selector);
		}
        return ApiResponseFactory.createFieldSelectorResponse(role, selector);
	}

    /**
     * Delete roles.
     * 
     * @param authUser the authenticated user
     * @param roleId the role id
     * @param request the http request
     * @return the api response
     * @throws APIRuntimeException if any error occurs
     * @since 1.1
     */
	@Override
	@DELETE
	@Path("/{roleId}")
	public ApiResponse deleteObject(
			@Auth AuthUser authUser,
			@PathParam("roleId") String roleId,
			@Context HttpServletRequest request) throws Exception {
		logger.info(String.format("deleteObject(%s)", roleId));

		if (!Utils.hasAdminRole(authUser))
			throw new APIRuntimeException(HttpServletResponse.SC_FORBIDDEN);

        Role role = getExistingRole(new TCID(roleId));

        try {
            dao.deleteRole(roleId);
        } catch (Exception e) {
            logger.error("Failed to delete role.", e);
            throw new APIRuntimeException(SC_INTERNAL_SERVER_ERROR, e);
        }

        return ApiResponseFactory.createFieldSelectorResponse(role, null);
	}
	
	/**
	 * Assign a role to a user
	 */
	@POST
	@Path("/{roleId}/assign")
	public ApiResponse assignRole(
			@Auth AuthUser authUser,
			@PathParam("roleId") TCID roleId,
			@APIQueryParam(repClass = Role.class) QueryParameter query,
			@Context HttpServletRequest request) throws Exception {

        if (!Utils.hasAdminRole(authUser))
            throw new APIRuntimeException(HttpServletResponse.SC_FORBIDDEN);

		if(roleId == null)
			throw new APIRuntimeException(HttpServletResponse.SC_BAD_REQUEST, "roleId is required");

		logger.info(String.format("assignRole() roleId="+roleId.toString()));

		TCID operatorId = authUser.getUserId();

		FilterParameter filter = query.getFilter();
		String subjectId = (String) filter.get("subjectID");

		logger.info(String.format("assignRole() roleId="+roleId.toString()+" subjectId="+subjectId.toString()));

		Role role = new Role();
		role.setId(roleId);

		if (dao.checkRole(subjectId.toString(), roleId.toString()))
			return ApiResponseFactory.createResponse(role);

		return ApiResponseFactory.createResponse(dao.assign(roleId, new TCID(subjectId), operatorId));
	}
	
	/**
	 * Remove a role from subject
	 */
	@DELETE
	@Path("/{roleId}/deassign")
	public ApiResponse deassignRole(
			@Auth AuthUser authUser, 
			@PathParam("roleId") TCID roleId,
			@APIQueryParam(repClass = Role.class) QueryParameter query,
			@Context HttpServletRequest request) throws Exception {

        if (!Utils.hasAdminRole(authUser))
            throw new APIRuntimeException(HttpServletResponse.SC_FORBIDDEN);

		if(roleId == null)
			throw new APIRuntimeException(HttpServletResponse.SC_BAD_REQUEST, "roleId is required");

		logger.info(String.format("deAssignRole() roleId="+roleId.toString()));

		FilterParameter filter = query.getFilter();
		String subjectId = (String) filter.get("subjectID");

		Role role = new Role();
		role.setId(roleId);

		if (!dao.checkRole(subjectId.toString(), roleId.toString()))
			return ApiResponseFactory.createResponse(role);

		return ApiResponseFactory.createResponse(dao.deassign(roleId, new TCID(subjectId)));
	}
	
	/**
	 * Check whether a subject has role
	 */
	@GET
	@Path("/{roleId}/hasrole")
	public ApiResponse hasRole(
			@Auth AuthUser authUser,
			@PathParam("roleId") TCID roleId,
			@APIQueryParam(repClass = Role.class) QueryParameter query,
			@Context HttpServletRequest request) throws Exception {

		if ( roleId == null )
			throw new APIRuntimeException(HttpServletResponse.SC_BAD_REQUEST, "roleId is required.");

		logger.info(String.format("hasRole() roleId="+roleId.toString()));

		FilterParameter filter = query.getFilter();
		String subjectId = (String) filter.get("subjectID");

		Role role = new Role();
		role.setId(roleId);

		if (!dao.checkRole(subjectId, roleId.toString()))
			throw new APIRuntimeException(HttpServletResponse.SC_NOT_FOUND);

		return ApiResponseFactory.createResponse(role);
	}

	protected boolean hasField(FieldSelector selector, String field) {
		if(field==null)
			throw new IllegalArgumentException("field must be specified.");

		if(selector==null || selector.getSelectedFields()==null)
			return false;
		for(Iterator<String> iter= selector.getSelectedFields().iterator(); iter.hasNext();) {
			String specifiedField = iter.next();
			if(specifiedField.equals(field) || specifiedField.startsWith(field+"("))
				return true;
		}
		return false;
	}

    /**
     * Validate auth user and role
     * @param authUser the authenticated user
     * @param request the role POST/PUT request
     * @return the validated role
     * @throws APIRuntimeException if user is not admin, or if given role is invalid
     * @since 1.2
     */
    private Role validateRole(AuthUser authUser, PostPutRequest<Role> request) {
        if (!Utils.hasAdminRole(authUser))
            throw new APIRuntimeException(HttpServletResponse.SC_FORBIDDEN);

        if (request == null) {
            throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_MANDATORY, "Role"));
        }

        Role role = request.getParam();
        if (role == null) {
            throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_MANDATORY, "Role"));
        }

        if (Utils.isBlank(role.getRoleName())) {
            throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_MANDATORY, "Role name"));
        }
        return role;
    }

    /**
     * Fetch an existing role
     * @param roleId the id of role to fetch
     * @return the role found
     * @throws APIRuntimeException if given role id is invalid, or if role does not exist, or if any other error occurs
     * @since 1.2
     */
    private Role getExistingRole(TCID roleId) {
        if (!Utils.isValid(roleId)) {
            throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_INVALID, "Role id"));
        }

        Role role;
        try {
            role = dao.findRoleById(Utils.toLongValue(roleId));
        } catch (Exception e) {
            logger.error("Failed to get role.", e);
            throw new APIRuntimeException(SC_INTERNAL_SERVER_ERROR, e);
        }

        if (role == null)
            throw new APIRuntimeException(HttpServletResponse.SC_NOT_FOUND, String.format(MSG_TEMPLATE_NOT_EXIST, "Role"));

        return role;
    }
}
