package com.appirio.tech.core.service.identity.resource;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.request.PostPutRequest;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.api.v3.response.ApiResponseFactory;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.dao.PermissionPolicyDAO;
import com.appirio.tech.core.service.identity.dao.RoleDAO;
import com.appirio.tech.core.service.identity.perms.PermissionsPolicy;
import com.appirio.tech.core.service.identity.perms.PolicySubject;
import com.appirio.tech.core.service.identity.representation.Role;
import com.codahale.metrics.annotation.Timed;
import com.google.common.base.Optional;
import com.google.common.base.Strings;
import io.dropwizard.auth.Auth;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

// TODO: need a strategy on how to enforce crud on policies themselves
@Path("policies")
@Produces(MediaType.APPLICATION_JSON)
public class PoliciesResource {

	private static final Logger logger = LoggerFactory.getLogger(PoliciesResource.class);
	private static final String adminRoleId = "1";
	
	private static String DELEGATE_POLICY_LOADER_ROLE;
	
	private final PermissionPolicyDAO policyDao;
	private final RoleDAO roleDao;
	
	public PoliciesResource(PermissionPolicyDAO policyDao, RoleDAO roleDao) {
		this.policyDao = policyDao;
		this.roleDao = roleDao;
		
		Role r = roleDao.findRoleByName("Delegate Policy Loader");
		if (r == null) {
		    logger.error("No role found for 'Delegate Policy Loader'");
		    throw new IllegalStateException("Unexpected configuration - No role found for 'Delegate Policy Loader'");
		} else {
		    DELEGATE_POLICY_LOADER_ROLE = r.getId().toString(); 
		}
	}
	
	@GET
	@Timed
	public ApiResponse queryPolicies(
			@Auth AuthUser authUser,
			@QueryParam("resource") Optional<String> resourceParam,
			@QueryParam("userId") Optional<String> userId) {

		logger.debug("query policies for resource {}", resourceParam.orNull());

		final String resource = resourceParam.orNull();

		// TODO: load user groups
		final List<String> roles;
		final String userSubjectId;
		if (userId.isPresent() && !authUser.getUserId().toString().equals(userId.get())) {
		    logger.debug("request to load policies for user {}", userId.get());
		    if (!policyDao.checkRole(authUser.getUserId().toString(), DELEGATE_POLICY_LOADER_ROLE))
	            throw new APIRuntimeException(HttpServletResponse.SC_UNAUTHORIZED);
		    userSubjectId = userId.get();
		    List<Role> roleList = roleDao.getRolesBySubjectId(Long.parseLong(userSubjectId));
		    if (roleList == null) {
		        roles = Collections.emptyList();
		    } else {
		        roles = new ArrayList<>(roleList.size());
		        roleList.forEach(r -> roles.add(r.getRoleName()));
		    }
		} else {
		    roles = authUser.getRoles();
		    userSubjectId = authUser.getUserId().toString();
		}

		List<PolicySubject> policySubjects = new ArrayList<>(roles.size() + 1);

		// TODO: use enum for subjectType
		policySubjects.add(new PolicySubject(userSubjectId, "user"));
		roles.forEach(r -> policySubjects.add(new PolicySubject(r, "role")));

		List<PermissionsPolicy> policies;
		if (Strings.isNullOrEmpty(resource)) {
			policies = policyDao.getPolicies(policySubjects);
		} else {
			policies = policyDao.getPoliciesForResource(policySubjects, resource);
		}

		return ApiResponseFactory.createResponse(policies);
	}
	
	@GET
	@Timed
	@Path("{id}")
	public ApiResponse loadPolicy(
			@Auth AuthUser authUser,
			@PathParam("id") String id) {
		
		logger.debug("Loading policy {}", id.toString());
		
		final PermissionsPolicy policy = policyDao.loadPolicy(id);
		
		if (policy == null) {
			logger.warn("no policy with id {} to load", id);
			throw new APIRuntimeException(HttpServletResponse.SC_NOT_FOUND);
		}
		
		return ApiResponseFactory.createResponse(policy);
		
	}
	
	@PUT
	@Timed
	@Path("{id}")
	public ApiResponse updatePolicy(
			@Auth AuthUser authUser,
			@PathParam("id") String id,
			PostPutRequest<PermissionsPolicy> policyRequest) {

		logger.debug("Updating Policy "+id.toString());

		TCID operatorId = authUser.getUserId();
		if (!policyDao.checkRole(operatorId.toString(), adminRoleId))
			throw new APIRuntimeException(HttpServletResponse.SC_UNAUTHORIZED);

		final PermissionsPolicy policy = policyRequest.getParam();
		if (!id.equals(policy.getId().toString())) {
			throw new APIRuntimeException(HttpServletResponse.SC_BAD_REQUEST, "Path id does not match entity id");
		}
		if (policy.getPolicy() == null) {
			throw new APIRuntimeException(HttpServletResponse.SC_BAD_REQUEST, "policy is required");
		}

		final PermissionsPolicy updatedPolicy = policyDao.updatePolicy(authUser, policy);

		return ApiResponseFactory.createResponse(updatedPolicy);

	}
	
	@POST
	@Timed
	public ApiResponse createPolicy(
			@Auth AuthUser authUser,
			PostPutRequest<PermissionsPolicy> postRequest)
			throws Exception {
		logger.debug("Creating policy...");

		TCID operatorId = authUser.getUserId();
		if (!policyDao.checkRole(operatorId.toString(), adminRoleId))
			throw new APIRuntimeException(HttpServletResponse.SC_UNAUTHORIZED);

		PermissionsPolicy inputPolicy = postRequest.getParam();

		if (Strings.isNullOrEmpty(inputPolicy.getSubjectId())) {
			throw new APIRuntimeException(HttpServletResponse.SC_BAD_REQUEST, "subjectId is required");
		} else if (Strings.isNullOrEmpty(inputPolicy.getSubjectType())) {
			throw new APIRuntimeException(HttpServletResponse.SC_BAD_REQUEST, "subjectType is required");
		}
		PermissionsPolicy policy = policyDao.createPolicy(authUser, inputPolicy);

		return ApiResponseFactory.createCreatedResponse(policy.getId().toString(), new URI("policies/" + policy.getId()));
	}

}
