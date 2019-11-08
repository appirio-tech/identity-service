/**
 * Copyright (C) 2017 Topcoder Inc., All Rights Reserved.
 */
package com.appirio.tech.core.service.identity.dao;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.skife.jdbi.v2.TransactionIsolationLevel;
import org.skife.jdbi.v2.sqlobject.Bind;
import org.skife.jdbi.v2.sqlobject.BindBean;
import org.skife.jdbi.v2.sqlobject.GetGeneratedKeys;
import org.skife.jdbi.v2.sqlobject.SqlQuery;
import org.skife.jdbi.v2.sqlobject.SqlUpdate;
import org.skife.jdbi.v2.sqlobject.Transaction;
import org.skife.jdbi.v2.sqlobject.customizers.RegisterMapperFactory;
import org.skife.jdbi.v2.sqlobject.mixins.Transactional;
import org.skife.jdbi.v2.sqlobject.stringtemplate.UseStringTemplate3StatementLocator;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.dao.DaoBase;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.request.FieldSelector;
import com.appirio.tech.core.api.v3.util.jdbi.TCBeanMapperFactory;
import com.appirio.tech.core.service.identity.representation.Role;
import com.appirio.tech.core.service.identity.util.Utils;
import com.appirio.tech.core.service.identity.util.shiro.Shiro;

/**
 * DAO used to manage role.
 * 
 * <p>
 * Version 1.2 - ROLES MANAGEMENT API ENHANCEMENTS
 * - Added updateRole(), deleteRoleAssignmentsByRoleId(), update().
 * - Fixed a bug in deleteRole().
 * </p>
 *
 * @author TCSCODER
 * @version 1.2
 */
@UseStringTemplate3StatementLocator
@RegisterMapperFactory(TCBeanMapperFactory.class)
public abstract class RoleDAO implements DaoBase<Role>, Transactional<RoleDAO> {

	protected Shiro shiroSettings;

	public Shiro getShiroSettings() {
		return shiroSettings;
	}

	public void setShiroSettings(Shiro shiroSettings) {
		this.shiroSettings = shiroSettings;
	}
	
	@SqlQuery(" SELECT "
			+ " r.id AS id,"
			+ " r.name AS roleName,"
			+ " r.modifiedBy AS modifiedBy,"
			+ " r.modifiedAt AS modifiedAt,"
			+ " r.createdBy AS createdBy,"
			+ " r.createdAt AS createdAt"
			+ " FROM "
			+ " role r")
	public abstract List<Role> getAllRoles();

	@SqlQuery(" SELECT "
			+ " r.id AS id,"
			+ " r.name AS roleName,"
			+ " r.modifiedBy AS modifiedBy,"
			+ " r.modifiedAt AS modifiedAt,"
			+ " r.createdBy AS createdBy,"
			+ " r.createdAt AS createdAt"
			+ " FROM "
			+ " role r"
			+ " WHERE r.id IN "
			+ " (SELECT "
			+ " role_id "
			+ " FROM "
			+ " role_assignment "
			+ " WHERE "
			+ " subject_id = :subjectId)")
	public abstract List<Role> getRolesBySubjectId(@Bind("subjectId") long subjectId);

	@SqlQuery(" SELECT "
			+ " r.id AS id,"
			+ " r.name AS roleName,"
			+ " r.modifiedBy AS modifiedBy,"
			+ " r.modifiedAt AS modifiedAt,"
			+ " r.createdBy AS createdBy,"
			+ " r.createdAt AS createdAt"
			+ " FROM "
			+ " role r"
			+ " WHERE r.id = :id")
	public abstract Role findRoleById(@Bind("id") long id);

	@SqlQuery(" SELECT "
			+ " r.id AS id,"
			+ " r.name AS roleName,"
			+ " r.modifiedBy AS modifiedBy,"
			+ " r.modifiedAt AS modifiedAt,"
			+ " r.createdBy AS createdBy,"
			+ " r.createdAt AS createdAt"
			+ " FROM "
			+ " role r"
			+ " WHERE r.name = :roleName")
	public abstract Role findRoleByName(@Bind("roleName") String roleName);

	@SqlUpdate(" INSERT INTO role ( "
			+ " name, "
			+ " createdBy, "
			+ " createdAt, "
			+ " modifiedBy, "
			+ " modifiedAt "
			+ ") VALUES ( "
			+ " :roleName, "
			+ " :subjectId, "
			+ " now(), "
			+ " :subjectId, "
			+ " now() "
			+ " ) ")
	@GetGeneratedKeys
	public abstract long createNewRole(@Bind("roleName") String roleName, @Bind("subjectId") long subjectId) throws Exception;

    /**
     * Update role.
     * @param role the role to update
     * @return update result
     * @since 1.2
     */
    @SqlUpdate(" UPDATE role SET "
            + " name = :r.roleName, "
            + " modifiedBy = :r.modifiedBy, "
            + " modifiedAt = :r.modifiedAt "
            + " WHERE id = :r.id ")
    @GetGeneratedKeys
    public abstract long updateRole(@BindBean("r") Role role) throws Exception;
	
	@SqlQuery(" SELECT "
			+ " p.permission_id AS id "
			+ " FROM "
			+ " permission_assignment p"
			+ " WHERE "
			+ " p.role_id = :roleId" )
	public abstract List<TCID> getPerms(@Bind("roleId") long roleId);

	@SqlQuery(" SELECT "
			+ " rs.subject_id AS id "
			+ " FROM "
			+ " role_assignment rs"
			+ " WHERE "
			+ " rs.role_id = :roleId" )
	public abstract List<TCID> getSubs(@Bind("roleId") long roleId);

	@SqlUpdate(" INSERT INTO role_assignment ( "
			+ " role_id, "
			+ " subject_id, "
			+ " createdBy, "
			+ " createdAt, "
			+ " modifiedBy, "
			+ " modifiedAt "
			+ ") VALUES ( "
			+ " :roleId, "
			+ " :subjectId, "
			+ " :operatorId, "
			+ " now(), "
			+ " :operatorId, "
			+ " now() "
			+ " ) ")
	public abstract int assignRole(@Bind("roleId") long roleId,
								   @Bind("subjectId") long subjectId,
								   @Bind("operatorId") long operatorId);
	
	@SqlUpdate(" DELETE FROM role_assignment "
			+ " WHERE "
			+ " role_id = :roleId "
			+ " AND "
			+ " subject_id = :subjectId" )
	public abstract int deassignRole(@Bind("roleId") long roleId, @Bind("subjectId") long subjectId);

    /**
     * Delete rows in role_assignment by role id.
     * @param roleId the role id
     * @return update result
     * @since 1.2
     */
    @SqlUpdate(" DELETE FROM role_assignment "
            + " WHERE "
            + " role_id = :roleId " )
    public abstract int deleteRoleAssignmentsByRoleId(@Bind("roleId") String roleId);

	@SqlUpdate( " DELETE FROM role "
			+ " WHERE "
			+ " id = :id " )
	public abstract int deleteRoleById(@Bind("id") String id);


	@Override
	public Role populateById(FieldSelector selector, TCID id) throws Exception {
		if( id == null || !Utils.isValid(id))
			throw new IllegalArgumentException("Specified id is invalid. id: "+id);

		return findRoleById(Utils.toLongValue(id));
	}

	@Transaction(TransactionIsolationLevel.READ_COMMITTED)
	public Role create(Role role, TCID operatorId)  throws Exception{

		String roleName = role.getRoleName();
		Role existingRole = findRoleByName(roleName);
		if (existingRole != null)
			return existingRole;

		long lastId = createNewRole(roleName, Utils.toLongValue(operatorId));
		TCID id = new TCID(lastId);
		role.setId(id);
		
		if (role.getSubjects() != null) {
			for (TCID subjectId : role.getSubjects()) {
				assignRole(Utils.toLongValue(id), Utils.toLongValue(subjectId), Utils.toLongValue(operatorId));
			}
		}
		return role;
	}

    /**
     * Update role.
     * @param role the role to update
     * @return role id
     * @throws IllegalArgumentException if given role is null, or role id is invalid
     * @since 1.2
     */
    @Override
    @Transaction(TransactionIsolationLevel.READ_COMMITTED)
    public TCID update(Role role)  throws Exception{
        if(role == null)
            throw new IllegalArgumentException("role must be specified.");
        if(!Utils.isValid(role.getId()))
            throw new IllegalArgumentException("Specified id is invalid. id: " + role.getId());
        
        updateRole(role);
        
        if (role.getSubjects() != null) {
	        deleteRoleAssignmentsByRoleId(role.getId().getId());
			for (TCID subjectId : role.getSubjects()) {
				assignRole(Utils.toLongValue(role.getId()), Utils.toLongValue(subjectId), Utils.toLongValue(role.getModifiedBy()));
			}
		}
        
        return role.getId();
    }

	public Role getSubjects(TCID roleId) {

		if( roleId == null || !Utils.isValid(roleId))
			throw new IllegalArgumentException("Specified id is invalid. id: "+roleId);

		List<TCID> subs = getSubs(Utils.toLongValue(roleId));

		Role role = findRoleById(Utils.toLongValue(roleId));
		Set<TCID> subSet = new HashSet<TCID>();

		for (TCID s : subs) {
			subSet.add(s);
		}
		role.setSubjects(subSet);
		role.setId(roleId);
		return role;
	}

	@Transaction(TransactionIsolationLevel.READ_COMMITTED)
	public TCID assign(TCID roleId, TCID subjectId, TCID operatorId) {

		assignRole(Utils.toLongValue(roleId), Utils.toLongValue(subjectId), Utils.toLongValue(operatorId));
		
		return roleId;
	}

	@Transaction(TransactionIsolationLevel.READ_COMMITTED)
	public TCID deassign(TCID roleId, TCID subjectId) {
		
		deassignRole(Utils.toLongValue(roleId), Utils.toLongValue(subjectId));
		
		return roleId;
	}


    /**
     * Delete role.
     * @param id the id of the role to delete
     * @return role id
     * @throws IllegalArgumentException if the id is invalid
     * @since 1.1
     */
	@Transaction(TransactionIsolationLevel.READ_COMMITTED)
	public TCID deleteRole(String id) {

		if( id == null )
			throw new IllegalArgumentException("Specified id is invalid. id: "+id);
        TCID tcId = new TCID(id);
        if(!Utils.isValid(tcId))
            throw new IllegalArgumentException("Specified id is invalid. id: "+id);

        deleteRoleAssignmentsByRoleId(id);
		deleteRoleById(id);

		return tcId;
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
