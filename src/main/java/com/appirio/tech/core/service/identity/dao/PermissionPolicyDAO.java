package com.appirio.tech.core.service.identity.dao;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.dao.DaoBase;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.util.jdbi.TCBeanMapperFactory;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.perms.PermissionsPolicy;
import com.appirio.tech.core.service.identity.perms.Policy;
import com.appirio.tech.core.service.identity.perms.PolicySubject;
import com.appirio.tech.core.service.identity.util.Utils;
import com.appirio.tech.core.service.identity.util.shiro.Shiro;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.log4j.Logger;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.skife.jdbi.v2.TransactionIsolationLevel;
import org.skife.jdbi.v2.sqlobject.*;
import org.skife.jdbi.v2.sqlobject.customizers.RegisterMapperFactory;
import org.skife.jdbi.v2.sqlobject.mixins.Transactional;
import org.skife.jdbi.v2.sqlobject.stringtemplate.UseStringTemplate3StatementLocator;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@UseStringTemplate3StatementLocator
public abstract class PermissionPolicyDAO implements DaoBase<PermissionsPolicy>, Transactional<PermissionPolicyDAO> {

	private static final Logger logger = Logger.getLogger(PermissionPolicyDAO.class);
	private static final ObjectMapper MAPPER = new ObjectMapper();

	protected Shiro shiroSettings;

	public Shiro getShiroSettings() {
		return shiroSettings;
	}

	public void setShiroSettings(Shiro shiroSettings) {
		this.shiroSettings = shiroSettings;
	}

	@SqlUpdate(" INSERT INTO permission_policy ( "
			+ " id, "
			+ " subjectId, "
			+ " subjectType, "
			+ " resource, "
			+ " createdBy, "
			+ " createdAt, "
			+ " modifiedBy, "
			+ " modifiedAt, "
			+ " policy "
			+ ") VALUES ( "
			+ " :id, "
			+ " :p.subjectId, "
			+ " :p.subjectType, "
			+ " :p.resource, "
			+ " :userId, "
			+ " :p.createdAt, "
			+ " :userId, "
			+ " :p.modifiedAt, "
			+ " :policyJson "
			+ " ) ")
	abstract int create(@BindBean("p") PermissionsPolicy policy, @Bind("id") String id, @Bind("policyJson") String policyJson, @Bind("userId") long userId);

	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlQuery(" SELECT "
			+ " p.id AS id,"
			+ " p.subjectId AS subjectId,"
			+ " p.subjectType AS subjectType,"
			+ " p.resource AS resource,"
			+ " p.createdBy AS createdBy,"
			+ " p.createdAt AS createdAt,"
			+ " p.modifiedBy AS modifiedBy,"
			+ " p.modifiedAt AS modifiedAt,"
			+ " p.policy AS policyJson"
			+ " FROM "
			+ " permission_policy p"
			+ " WHERE p.id = :id")
	public abstract PermissionsPolicy findPolicyById(@Bind("id") String id);

	@SqlUpdate(" UPDATE permission_policy  SET "
			+ " modifiedBy=:userId, "
			+ " modifiedAt=:p.modifiedAt, "
			+ " policy=:policyJson "
			+ " WHERE id = :id"
			)
	abstract int update(@BindBean("p") PermissionsPolicy policy, @Bind("id") String id, @Bind("policyJson") String policyJson, @Bind("userId") long userId);

	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlQuery(" SELECT "
			+ " p.id AS id,"
			+ " p.subjectId AS subjectId,"
			+ " p.subjectType AS subjectType,"
			+ " p.resource AS resource,"
			+ " p.createdBy AS createdBy,"
			+ " p.createdAt AS createdAt,"
			+ " p.modifiedBy AS modifiedBy,"
			+ " p.modifiedAt AS modifiedAt,"
			+ " p.policy AS policyJson"
			+ " FROM "
			+ " permission_policy p"
			+ " WHERE p.subjectId = :subjectId AND p.subjectType = :subjectType")
	public abstract List<PermissionsPolicy> getAllPoliciesFromDB(@Bind("subjectId") String subjectId, @Bind("subjectType") String subjectType);

	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlQuery(" SELECT "
			+ " p.id AS id,"
			+ " p.subjectId AS subjectId,"
			+ " p.subjectType AS subjectType,"
			+ " p.resource AS resource,"
			+ " p.createdBy AS createdBy,"
			+ " p.createdAt AS createdAt,"
			+ " p.modifiedBy AS modifiedBy,"
			+ " p.modifiedAt AS modifiedAt,"
			+ " p.policy AS policyJson"
			+ " FROM "
			+ " permission_policy p"
			+ " WHERE p.resource = :resource AND p.subjectId = :subjectId AND p.subjectType = :subjectType")
    public abstract PermissionsPolicy getPolicyForResource(@Bind("subjectId") String subjectId,
            @Bind("subjectType") String subjectType, @Bind("resource") String resource);


	@Transaction(TransactionIsolationLevel.READ_COMMITTED)
	public PermissionsPolicy createPolicy(AuthUser user, PermissionsPolicy policy) {

		policy.setId(new TCID(UUID.randomUUID().toString()));

		DateTime now = new DateTime(DateTimeZone.UTC);
		policy.setModifiedAt(now);
		policy.setModifiedBy(user.getUserId());

		try {
			String policyJson = MAPPER.writeValueAsString(policy.getPolicy());
			create(policy, policy.getId().toString(), policyJson, Utils.toLongValue(user.getUserId()));
		} catch (JsonProcessingException e) {
			e.printStackTrace();
			logger.info("createPolicy: JsonProcessingException "+e.getStackTrace());
			throw new APIRuntimeException(HttpServletResponse.SC_BAD_REQUEST, "Invalid Policy");
		}

		return policy;
	}

	public PermissionsPolicy loadPolicy(String id) {

		PermissionsPolicy policy = findPolicyById(id);
		if (policy == null)
			return policy;

		try {
			Policy p = MAPPER.readValue(policy.getPolicyJson(), Policy.class);
			policy.setPolicy(p);
		} catch (IOException e) {
			e.printStackTrace();
			logger.info("loadPolicy: IOException " + e.getStackTrace());
			throw new APIRuntimeException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error occured while retrieving policy");
		}
		return policy;
	}

	public PermissionsPolicy updatePolicy(AuthUser user, PermissionsPolicy policy) {

		PermissionsPolicy existingPolicy = findPolicyById(policy.getId().toString());

		if (existingPolicy == null) {
			throw new APIRuntimeException(HttpServletResponse.SC_BAD_REQUEST,
					"No existing policy found to update. Policies cannot be updated with a new subjectId, subjectType, or resource");
		}

		DateTime now = new DateTime(DateTimeZone.UTC);
		existingPolicy.setModifiedAt(now);
		existingPolicy.setModifiedBy(user.getUserId());
		existingPolicy.setPolicy(policy.getPolicy());

		try {
			String policyJson = MAPPER.writeValueAsString(policy.getPolicy());
			update(existingPolicy, existingPolicy.getId().toString(), policyJson, Utils.toLongValue(user.getUserId()));
		} catch (JsonProcessingException e) {
			e.printStackTrace();
			logger.info("updatePolicy: JsonProcessingException " + e.getStackTrace());
			throw new APIRuntimeException(HttpServletResponse.SC_BAD_REQUEST, "Invalid Policy");
		}
		return existingPolicy;
	}

	public List<PermissionsPolicy> getPolicies(List<PolicySubject> policySubjects) {

		List<PermissionsPolicy> policies = new ArrayList<>();

		for (PolicySubject ps : policySubjects) {
			policies.addAll(getAllPolicies(ps.getSubjectId(), ps.getSubjectType()));
		}

		try {
			for (PermissionsPolicy policy : policies) {
				Policy p = MAPPER.readValue(policy.getPolicyJson(), Policy.class);
				policy.setPolicy(p);
			}
		} catch (IOException e) {
			e.printStackTrace();
			logger.info("getPolicies : IOException " + e.getStackTrace());
			throw new APIRuntimeException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error occured while retrieving policy");
		}

		return policies;
	}

	public List<PermissionsPolicy> getAllPolicies(String subjectId, String subjectType) {

		return getAllPoliciesFromDB(subjectId, subjectType);
	}

	public List<PermissionsPolicy> getPoliciesForResource(List<PolicySubject> policySubjects, String resource) {

		List<PermissionsPolicy> policies = new ArrayList<>(policySubjects.size());

		try {
		    for (PolicySubject ps : policySubjects) {
		        final PermissionsPolicy permPol = getPolicyForResource(ps.getSubjectId(), ps.getSubjectType(), resource);
		        if (permPol != null) {
		            permPol.setPolicy(MAPPER.readValue(permPol.getPolicyJson(), Policy.class));
		            policies.add(permPol);
		        }
		    }
		} catch (IOException e) {
			e.printStackTrace();
			logger.info("getPoliciesForResource: IOException " + e.getStackTrace());
			throw new APIRuntimeException(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error occured while retrieving policy");
		}

		return policies;
	}

	public boolean checkRole(String subjectId, String roleId) throws APIRuntimeException {

		if(!shiroSettings.isUseShiroAuthorization())
			throw new APIRuntimeException(HttpServletResponse.SC_NOT_IMPLEMENTED);

		String realmName = "DAORealm";
		PrincipalCollection principals = new SimplePrincipalCollection(subjectId.toString(), realmName);
		Subject currentUser = new Subject.Builder(SecurityUtils.getSecurityManager()).principals(principals).buildSubject();

		return currentUser.hasRole(roleId.toString());
	}

}