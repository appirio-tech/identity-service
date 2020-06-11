/*
 * Copyright (C) 2017 Topcoder Inc., All Rights Reserved.
 */
package com.appirio.tech.core.service.identity.resource;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.request.FieldSelector;
import com.appirio.tech.core.api.v3.request.PostPutRequest;
import com.appirio.tech.core.api.v3.request.QueryParameter;
import com.appirio.tech.core.api.v3.request.annotation.APIFieldParam;
import com.appirio.tech.core.api.v3.request.annotation.APIQueryParam;
import com.appirio.tech.core.api.v3.request.annotation.AllowAnonymous;
import com.appirio.tech.core.api.v3.resource.DDLResource;
import com.appirio.tech.core.api.v3.resource.GetResource;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.api.v3.response.ApiResponseFactory;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.dao.GroupDAO;
import com.appirio.tech.core.service.identity.dao.GroupInformixDAO;
import com.appirio.tech.core.service.identity.representation.Group;
import com.appirio.tech.core.service.identity.representation.GroupMembership;
import com.appirio.tech.core.service.identity.representation.GroupMembership.MembershipType;
import com.appirio.tech.core.service.identity.representation.SecurityGroup;
import com.appirio.tech.core.service.identity.util.Utils;
import com.codahale.metrics.annotation.Timed;
import io.dropwizard.auth.Auth;
import org.apache.log4j.Logger;
import org.joda.time.DateTime;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.util.ArrayList;
import java.util.List;

import static com.appirio.tech.core.service.identity.util.Constants.MSG_TEMPLATE_DUPLICATED;
import static com.appirio.tech.core.service.identity.util.Constants.MSG_TEMPLATE_INVALID;
import static com.appirio.tech.core.service.identity.util.Constants.MSG_TEMPLATE_MANDATORY;
import static com.appirio.tech.core.service.identity.util.Constants.MSG_TEMPLATE_NOT_EXIST;
import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static javax.servlet.http.HttpServletResponse.SC_NOT_FOUND;

/**
 * API resource to manage groups.
 *
 * <p>
 * Version 1.1 - GROUP AND MEMBERSHIP MANAGEMENT API
 * - Implemented updateObject, deleteObject and getObject methods
 * - Added getMembers method
 * </p>
 *
 * <p>
 * Version 1.2 - GROUPS API ENHANCEMENTS
 * - Updated authorization logic based on the new "privateGroup" and "selfRegister" fields
 * - Added isUserMemberOfGroup and validateAdminRoleOrPrivateGroupMembership, validateAuthUser, validateMembership methods
 * </p>
 *
 * <p>
 * Changes in the version 1.3 in TC Identity Service - Groups API Return All Sub-groups v1.0
 * - add getGroup method for the endpoint groups/getGroup/{groupId} to get the sub group by one level or recursively.
 * </p>
 * 
 * <p>
 * Changes in the version 1.4 72h TC Identity Service API Enhancements v1.0
 * - add endpoints to create group in the informix, get single membership, get member count for a group.
 * </p>
 *
 * @author TCSCODER
 * @version 1.4
 */
@Path("groups")
@Produces(MediaType.APPLICATION_JSON)
public class GroupResource implements GetResource<Group>, DDLResource<Group> {

	private static final Logger logger = Logger.getLogger(GroupResource.class);

	/**
	 * Represents the read scopes for machine token validation.
	 */
	private static final String[] readScopes = {"read:groups", "write:groups", "all:groups"};

	/**
	 * Represents the write scopes for machine token validation
	 */
	private static final String[] writeScopes = {"write:groups", "all:groups"};

	/**
	 * Represents the DAO For Group
	 */
	private GroupDAO groupDao;

	/**
     * The groupInformixDao used to manage the group information in the informix database
     */
	private GroupInformixDAO groupInformixDao;
	
	public GroupResource() {
	}

	/**
	 * Create instance
	 * 
	 * @param groupDao the group dao
	 * @param groupInformixDao the group informix dao
	 */
	public GroupResource(GroupDAO groupDao, GroupInformixDAO groupInformixDao) {
		this.groupDao = groupDao;
		this.groupInformixDao = groupInformixDao;
	}

	/**
	 * Creation of new group
	 */
	@Override
	@POST
	@Timed
	public ApiResponse createObject(
			@Auth AuthUser authUser,
			@Valid PostPutRequest<Group> postRequest,
			@Context HttpServletRequest request) {
		logger.info("createObject()");

		Utils.checkAccess(authUser, writeScopes, Utils.AdminRoles);

		Group group = validateGroup(postRequest);

		if (this.groupDao.groupExists(group.getName())) {
			throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_DUPLICATED, group.getName()));
		}

		logger.debug(String.format("creating group: %s", group.getName()));
		try {
			if (!authUser.isMachine()) {
				group.setCreatedBy(authUser.getUserId());
			}
			group.setCreatedAt(DateTime.now());
			if (group.getPrivateGroup() == null) {
				group.setPrivateGroup(true);
			}
			if (group.getSelfRegister() == null) {
				group.setSelfRegister(false);
			}
			group = this.groupDao.create(group);
		} catch (Exception e) {
			logger.error("Failed to create group.", e);
			throw new APIRuntimeException(SC_INTERNAL_SERVER_ERROR, e);
		}

		return ApiResponseFactory.createFieldSelectorResponse(group, null);
	}
	
	/**
     * Create security group
     *
     * @param authUser the authUser to use
     * @param postRequest the postRequest to use
     * @throws APIRuntimeException if any error occurs
     * @return the ApiResponse result
     */
    @POST
    @Path("/securityGroups")
    @Timed
    public ApiResponse createSecurityGroup(
            @Auth AuthUser authUser,
            @Valid PostPutRequest<SecurityGroup> postRequest) {

        logger.info("createSecurityGroup()");

		Utils.checkAccess(authUser, writeScopes, Utils.AdminRoles);

        if (postRequest == null) {
            throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_MANDATORY, "Group"));
        }

        if (postRequest.getParam() == null) {
            throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_MANDATORY, "Group"));
        }
        SecurityGroup group = postRequest.getParam();
        if (Utils.isBlank(group.getName())) {
            throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_MANDATORY, "Name"));
        }
        
        if (!Utils.checkStringLength(group.getName(), 2, 50)) {
            throw new APIRuntimeException(SC_BAD_REQUEST, "Length of Name in character should be between 2 and 50");
        }

        if (this.groupInformixDao.findGroupByName(group.getName()) != null) {
            throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_DUPLICATED, group.getName()));
        }
        if (this.groupInformixDao.findGroupById(group.getId()) != null) {
            throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_DUPLICATED, group.getId()));
        }

        logger.debug(String.format("creating group: %s", group.getName()));
        try {
			if (!authUser.isMachine()) {
				group.setCreateUserId(Long.valueOf(authUser.getUserId().getId()));
			}
            this.groupInformixDao.createGroup(group);
        } catch (Exception e) {
            logger.error("Failed to create group.", e);
            throw new APIRuntimeException(SC_INTERNAL_SERVER_ERROR, e);
        }

        return ApiResponseFactory.createFieldSelectorResponse(group, null);
    }
    
    /**
     * Get single membership by group id
     *
     * @param authUser the authenticated user
     * @param groupId the group id
     * @param memberId the member id
     * @throws APIRuntimeException if any error occurs
     * @return the api response result
     *
     */
    @GET
    @Path("/{groupId}/singleMember/{memberId}")
    @Timed
    public ApiResponse getSingleMember(
            @Auth AuthUser authUser,
            @PathParam("groupId") TCID groupId,
            @PathParam("memberId") TCID memberId) {

        logger.info(String.format("getSingleMember(%s, %s)", groupId, memberId));

        // Check group exists
        getExistingGroup(groupId);

        try {
            GroupMembership membership = groupDao.findMembershipByGroupAndMember(Utils.toLongValue(groupId), Utils.toLongValue(memberId));
            if (membership == null) {
                throw new APIRuntimeException(SC_NOT_FOUND, "The member id is not found:" + memberId);
            }
            return ApiResponseFactory.createResponse(membership);
        } catch (NumberFormatException nfe) {
            throw new APIRuntimeException(SC_BAD_REQUEST, nfe);
        } catch (APIRuntimeException are) {
            throw are;
        } catch (Exception e) {
            logger.error("Failed to get single member.", e);
            throw new APIRuntimeException(SC_INTERNAL_SERVER_ERROR, e);
        }
    }
    
    /**
     * Get members count by group id
     * 
     *
     * @param groupId the group id
     * @param includeSubGroups a flag to indicate whether to get the count of members in the root group or 
     *        including all subgroups recursively
     * @return the api response result
     * @throws APIRuntimeException if any error occurs
     */
    @GET
    @Path("/{groupId}/membersCount")
    @Timed
    @AllowAnonymous
    public ApiResponse getMembersCount(
            @PathParam("groupId") TCID groupId,
            @QueryParam("includeSubGroups") boolean includeSubGroups) {

        logger.info(String.format("getMemberCount(%s, %s)", groupId, includeSubGroups));

        // Check group exists
        Group group = getExistingGroup(groupId);

        if (includeSubGroups) {
            this.getSubGroupsRecursively(group);
        }

        try {
            List<Long> groupIds = new ArrayList<>();
            this.collectGroupIds(group, groupIds);
            int count = groupDao.getMemberCount(groupIds, 1);
            return ApiResponseFactory.createResponse(new TCID(count));
        } catch (Exception e) {
            logger.error("Failed to get member count.", e);
            throw new APIRuntimeException(SC_INTERNAL_SERVER_ERROR, e);
        }
    }

    /**
     * Collect group ids
     *
     * @param group the group to use
     * @param groupIds the groupIds to use
     */
    private void collectGroupIds(Group group, List<Long> groupIds) {
        groupIds.add(Utils.toLongValue(group.getId()));
        if (group.getSubGroups() != null) {
            for (Group sub : group.getSubGroups()) {
                collectGroupIds(sub, groupIds);
            }
        }
    }

	/**
	 * Validate auth user and group
	 * @param request the group POST/PUT request
	 * @return the validated group
	 * @throws APIRuntimeException if user is not admin, or if given group is invalid
	 * @since 1.1
	 */
	private Group validateGroup(PostPutRequest<Group> request) {
		if (request == null) {
			throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_MANDATORY, "Group"));
		}

		Group group = request.getParam();
		if (group == null) {
			throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_MANDATORY, "Group"));
		}

		if (Utils.isBlank(group.getName())) {
			throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_MANDATORY, "Name"));
		}

		if (!Utils.checkStringLength(group.getName(), 2, 50)) {
			throw new APIRuntimeException(SC_BAD_REQUEST, "Length of Name in character should be between 2 and 50");
		}

		if (!Utils.checkStringLength(group.getDescription(), null, 500)) {
			throw new APIRuntimeException(SC_BAD_REQUEST, "Maximum length of Description is 500");
		}
		return group;
	}

	/**
	 * Validate a group membership
	 * @param request The membership POST/PUT request
	 * @since 1.1
	 */
	private void validateMembership(PostPutRequest<GroupMembership> request) {
		if (request == null) {
			throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_MANDATORY, "GroupMembership"));
		}

		GroupMembership groupMembership = request.getParam();
		if (groupMembership == null) {
			throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_MANDATORY, "GroupMembership"));
		}

		if (groupMembership.getMemberId() == null) {
			throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_MANDATORY, "memberId"));
		}

		if (groupMembership.getMembershipTypeId() == null) {
			throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_MANDATORY, "membershipType"));
		}
	}

	/**
	 * Update group
	 * @param authUser the authenticated user
	 * @param groupId the id of group to update
	 * @param putRequest the PUT request
	 * @param request the http request
	 * @return the api response
	 * @throws APIRuntimeException if user is not admin, or if given group is invalid,
	 *		 or if group does not exist, or if group name already exists, or if any other error occurs
	 * @since 1.1
	 */
	@Override
	@PUT
	@Path("/{groupId}")
	public ApiResponse updateObject(
			@Auth AuthUser authUser,
			@PathParam("groupId") String groupId,
			@Valid PostPutRequest<Group> putRequest,
			@Context HttpServletRequest request) {
		logger.info("updateObject()");

		Utils.checkAccess(authUser, writeScopes, Utils.AdminRoles);

		Group group = validateGroup(putRequest);

		Group existingGroup = getExistingGroup(new TCID(groupId));

		if (!group.getName().equals(existingGroup.getName()) && groupDao.groupExists(group.getName())) {
			// The name changes, check duplicate
			throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_DUPLICATED, group.getName()));
		}

		group.setId(existingGroup.getId());
		group.setCreatedAt(existingGroup.getCreatedAt());
		group.setCreatedBy(existingGroup.getCreatedBy());
		if (!authUser.isMachine()) {
			group.setModifiedBy(authUser.getUserId());
		}
		group.setModifiedAt(DateTime.now());

		if (group.getPrivateGroup() == null) {
			group.setPrivateGroup(existingGroup.getPrivateGroup());
		}
		if (group.getSelfRegister() == null) {
			group.setSelfRegister(existingGroup.getSelfRegister());
		}

		try {
			groupDao.update(group);
		} catch (Exception e) {
			logger.error("Failed to update group.", e);
			throw new APIRuntimeException(SC_INTERNAL_SERVER_ERROR, e);
		}

		return ApiResponseFactory.createFieldSelectorResponse(group, null);
	}

	/**
	 * Delete a group
	 * @param authUser the authenticated user
	 * @param groupId the id of group to delete
	 * @param request the http request
	 * @return the api response
	 * @throws APIRuntimeException if user is not admin, or if given group id is invalid,
	 *		 or if group does not exist, or if any other error occurs
	 * @since 1.1
	 */
	@Override
	@DELETE
	@Path("/{groupId}")
	public ApiResponse deleteObject(
			@Auth AuthUser authUser,
			@PathParam("groupId") String groupId,
			@Context HttpServletRequest request) {
		logger.info(String.format("deleteObject(%s)", groupId));

		Utils.checkAccess(authUser, writeScopes, Utils.AdminRoles);

		Group group = getExistingGroup(new TCID(groupId));

		try {
			groupDao.delete(group.getId());
		} catch (Exception e) {
			logger.error("Failed to delete group.", e);
			throw new APIRuntimeException(SC_INTERNAL_SERVER_ERROR, e);
		}

		return ApiResponseFactory.createFieldSelectorResponse(group, null);
	}

	/**
	 * Fetch an existing group
	 * @param groupId the id of group to fetch
	 * @return the group found
	 * @throws APIRuntimeException if given group id is invalid, or if group does not exist, or if any other error occurs
	 * @since 1.1
	 */
	private Group getExistingGroup(TCID groupId) {

		if (!Utils.isValid(groupId)) {
			throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_INVALID, "Group id"));
		}

		Group group;
		try {
			group = groupDao.findGroupById(Utils.toLongValue(groupId));
		} catch (Exception e) {
			logger.error("Failed to get group.", e);
			throw new APIRuntimeException(SC_INTERNAL_SERVER_ERROR, e);
		}

		if (group == null) {
			throw new APIRuntimeException(HttpServletResponse.SC_NOT_FOUND, String.format(MSG_TEMPLATE_NOT_EXIST, "Group"));
		}

		return group;
	}

	/**
	 * Fetch a particular group
	 * @param authUser the authenticated user
	 * @param groupId the id of group to fetch
	 * @param selector the fields selector
	 * @param request the http request
	 * @return the api response
	 * @throws APIRuntimeException if given group id is invalid, or if group does not exist, or if any other error occurs
	 * @since 1.1
	 */
	@Override
	@GET
	@Path("/{groupId}")
	@Timed
	public ApiResponse getObject(
			@Auth AuthUser authUser,
			@PathParam("groupId") TCID groupId,
			@APIFieldParam(repClass = Group.class) FieldSelector selector,
			@Context HttpServletRequest request) {
		logger.info(String.format("getObject(%s)", groupId));
		Group group = getExistingGroup(groupId);

		validateAdminRoleOrPrivateGroupMembership(authUser, group, readScopes, Utils.AdminRoles);

		return ApiResponseFactory.createFieldSelectorResponse(group, selector);
	}

	/**
	 * Get group with group id. Whether or not the sub groups are retrieved
	 * depends on the includeSubGroups and oneLevel.
	 *
	 * @param authUser the auth user
	 * @param groupId the group id
	 * @param selector the fields selector
	 * @param includeSubGroups a flag to indicate whether or not include the sub
	 *            groups
	 * @param oneLevel a flag to indicate whether or not get one level of sub
	 *            groups or all the sub groups recursively
	 * @return the response result
	 */
	@GET
	@Path("/{groupId}/getSubGroups")
	@Timed
	public ApiResponse getGroup(@Auth AuthUser authUser, @PathParam("groupId") TCID groupId,
          @APIFieldParam(repClass = Group.class) FieldSelector selector,
          @QueryParam("includeSubGroups") boolean includeSubGroups, @QueryParam("oneLevel") boolean oneLevel) {
		logger.info(String.format("getGroup(%s)", groupId));
		Group group = getExistingGroup(groupId);
		if (!includeSubGroups) {
		    return ApiResponseFactory.createFieldSelectorResponse(group, selector);
		}
		List<Group> subGroups = groupDao.findSubGroups(Long.parseLong(group.getId().getId()));
		group.setSubGroups(subGroups);
		if (oneLevel) {
		    return ApiResponseFactory.createFieldSelectorResponse(group, selector);
		}

		for (Group sub : subGroups) {
		    getSubGroupsRecursively(sub);
		}

		return ApiResponseFactory.createFieldSelectorResponse(group, selector);
	}
	
	/**
     * Get parent group for the given group id
     *
     * @param authUser the auth user
     * @param groupId the group id
     * @param selector the fields selector
     * @param oneLevel a flag to indicate whether or not get one level of sub
     *            groups or all the sub groups recursively
     * @return the response result
     */
    @GET
    @Path("/{groupId}/getParentGroup")
    @Timed
    public ApiResponse getParentGroup(@Auth AuthUser authUser, @PathParam("groupId") TCID groupId,
          @APIFieldParam(repClass = Group.class) FieldSelector selector, @DefaultValue("true") @QueryParam("oneLevel") boolean oneLevel) {
        logger.info(String.format("getParentGroups(%s)", groupId));
        Group group = getExistingGroup(groupId);

        List<Group> parentGroups = groupDao.findParentGroups(Long.parseLong(group.getId().getId()));
        if (parentGroups != null && parentGroups.size() > 0) {
            group.setParentGroup(parentGroups.get(0));
            if (!oneLevel) {
                getParentGroupsRecursively(parentGroups.get(0));
            }
        }
        
        

        return ApiResponseFactory.createFieldSelectorResponse(group, selector);
    }
    
    /**
     * Get parent groups recursively
     *
     * @param group the group to use
     */
    private void getParentGroupsRecursively(Group group) {
        List<Group> parentGroups = groupDao.findParentGroups(Long.parseLong(group.getId().getId()));
        if (parentGroups != null && parentGroups.size() > 0) {
            group.setParentGroup(parentGroups.get(0));
            getParentGroupsRecursively(parentGroups.get(0));
        }
    }

	/**
	 * Get the sub groups recursively
	 *
	 * @param parent the parent group
	 */
	private void getSubGroupsRecursively(Group parent) {
	    List<Group> subGroups = groupDao.findSubGroups(Long.parseLong(parent.getId().getId()));
	    if (subGroups == null || subGroups.size() == 0) {
	        return;
	    }
	    parent.setSubGroups(subGroups);
	    for (Group group : subGroups) {
	        getSubGroupsRecursively(group);
	    }
	}

	/**
	 * Get members by group id
	 *
	 * @param authUser the authenticated user
	 * @param groupId the group id
	 * @param request the http request
	 * @return the api response
	 * @throws APIRuntimeException if given group id is invalid, or if group does not exist, or if any other error occurs
	 * @since 1.1
	 */
	@GET
	@Path("/{groupId}/members")
	@Timed
	public ApiResponse getMembers(
			@Auth AuthUser authUser,
			@PathParam("groupId") TCID groupId,
			@Context HttpServletRequest request) {

		logger.info(String.format("getMembers(%s)", groupId));

		// Check group exists
		Group group = getExistingGroup(groupId);

		validateAdminRoleOrPrivateGroupMembership(authUser, group, readScopes, Utils.AdminRoles);

		try {
			List<GroupMembership> memberships = groupDao.findMembershipsByGroup(Utils.toLongValue(groupId));
			// If the group is private, then only a member of the group or an admin can access it

			return ApiResponseFactory.createResponse(
					memberships);
		} catch (Exception e) {
			logger.error("Failed to get members.", e);
			throw new APIRuntimeException(SC_INTERNAL_SERVER_ERROR, e);
		}
	}

	@Override
	@Timed
	public ApiResponse getObjects(
			@Auth AuthUser authUser,
			@APIQueryParam(repClass = Group.class)QueryParameter query,
			@Context HttpServletRequest request) {
		return null;
	}

	@GET
	@Timed
	public ApiResponse getObjects(
			@Auth AuthUser authUser,
			@QueryParam("memberId") TCID memberId,
			@QueryParam("membershipType") String membershipType,
			@Context HttpServletRequest request) {

		logger.info(String.format("getObjects(%s, %s)", memberId, membershipType));

		Utils.checkAccess(authUser, readScopes, null);

		// for admin and machine token
		if (authUser.isMachine() || Utils.hasAdminRole(authUser)) {
			if (memberId==null && Utils.isEmpty(membershipType)) {
				return ApiResponseFactory.createFieldSelectorResponse(groupDao.findAllGroups(), null);
			}
		} else {
			// ignore the query parameters, getting from the current auth user
			memberId = authUser.getUserId();
			membershipType = MembershipType.User.lowerName();
		}

		if(memberId==null || Utils.isEmpty(membershipType)) {
			throw new APIRuntimeException(SC_BAD_REQUEST, "Both memberId and membershipType are required if either of them is specified");
		}

		MembershipType membershipTypeEnum = MembershipType.get(membershipType);
		if(membershipTypeEnum==null) {
			throw new APIRuntimeException(SC_BAD_REQUEST, "Unsupported MembershipType: " + membershipType);
		}

		return ApiResponseFactory.createFieldSelectorResponse(
				groupDao.findGroupsByMember(Utils.toLongValue(memberId), membershipTypeEnum), null);
	}

	/**
	 * Add a member to the specified group
	 */
	@POST
	@Path("/{resourceId}/members")
	@Timed
	public ApiResponse addMember(
			@Auth AuthUser authUser,
			@PathParam("resourceId") TCID groupId,
			@Valid PostPutRequest<GroupMembership> postRequest,
			@Context HttpServletRequest request) {

		logger.info("addMember()");

		Utils.checkAccess(authUser, writeScopes, null);

		validateMembership(postRequest);

		GroupMembership membership = postRequest.getParam();

		if (this.groupDao.membershipExists(Utils.toLongValue(groupId), membership.getMemberId())) {
			throw new APIRuntimeException(SC_BAD_REQUEST, String.format(MSG_TEMPLATE_DUPLICATED, "Membership"));
		}

		Group group = getExistingGroup(groupId);

		// only admins or self registering users are allowed (if the group allows self register)
		if(!authUser.isMachine() && !Utils.hasAdminRole(authUser) && !(group.getSelfRegister() && membership.getMemberId().toString().equals(authUser.getUserId().getId()))) {
			throw new APIRuntimeException(SC_FORBIDDEN, "Forbidden");
		}

		membership.setGroupId(Utils.toLongValue(groupId));

		logger.debug(String.format("adding member(%d, %s) to group(%d)", membership.getMemberId(), membership.getMembershipType(), membership.getGroupId()));
System.out.println(String.format("adding member(%d, %s) to group(%d)", membership.getMemberId(), membership.getMembershipType(), membership.getGroupId()));

		try {
			if (!authUser.isMachine()) {
				membership.setCreatedBy(authUser.getUserId());
			}
			membership.setCreatedAt(DateTime.now());
			membership = this.groupDao.addMembership(membership);
		} catch (Exception e) {
			logger.error("Failed to add member.", e);
			//throw new APIRuntimeException(SC_INTERNAL_SERVER_ERROR, Constants.MSG_FATAL_ERROR);
			throw new APIRuntimeException(SC_INTERNAL_SERVER_ERROR, e);
		}

		return ApiResponseFactory.createFieldSelectorResponse(membership, null);
	}

	/**
	 * Remove a member from specified group
	 */
	@DELETE
	@Path("/{groupId}/members/{membershipId}")
	public ApiResponse removeMember(
			@Auth AuthUser authUser,
			@PathParam("groupId") TCID groupId,
			@PathParam("membershipId") TCID membershipId,
			@Context HttpServletRequest request) {

		logger.info(String.format("removeMember(%s, %s)", groupId, membershipId));

		Utils.checkAccess(authUser, writeScopes, null);

		long id = Utils.toLongValue(membershipId);
		GroupMembership membership = groupDao.findMembership(id);
		Group group = getExistingGroup(groupId);

		if(membership==null) {
			throw new APIRuntimeException(SC_NOT_FOUND, "Membership does not exist."); //TODO
		}

		// only admins or self registering users are allowed (if the group allows self register)
		if(!authUser.isMachine() && !Utils.hasAdminRole(authUser) && !(group.getSelfRegister() && membership.getMemberId().toString().equals(authUser.getUserId().getId()))) {
			throw new APIRuntimeException(SC_FORBIDDEN, "Forbidden");
		}

		groupDao.removeMembership(id);

		return ApiResponseFactory.createFieldSelectorResponse(membership, null);
	}

	/**
	 * Check if the group is private, only a member of the group or an admin can access it
	 * @param authUser The authenticated user
	 * @param group The group to check against
	 * @since 1.2
	 */
	private void validateAdminRoleOrPrivateGroupMembership(AuthUser authUser, Group group, String[] allowedScopes, String[] allowedRoles) {
		if (!group.getPrivateGroup()) {
			return;
		}

		if (authUser.isMachine() && allowedScopes != null) {
			for (String allowedScope : allowedScopes) {
				if (authUser.getScope().contains(allowedScope)) {
					return;
				}
			}
			return;
		} else {
			if (allowedRoles != null) {
				for (String role : allowedRoles) {
					if (authUser.getRoles() != null && authUser.getRoles().contains(role)) {
						return;
					}
				}
			}
		}

		if (groupDao.checkMemberOfGroup(Utils.toLongValue(authUser.getUserId()), Utils.toLongValue(group.getId())) == 1) {
			return;
		}
		throw new APIRuntimeException(SC_FORBIDDEN, "Forbidden");
	}
}
