/**
 * Copyright (C) 2017 Topcoder Inc., All Rights Reserved.
 */
package com.appirio.tech.core.service.identity.dao;

import static com.appirio.tech.core.service.identity.representation.GroupMembership.MembershipType;

import java.util.List;

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
import org.skife.jdbi.v2.unstable.BindIn;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.dao.DaoBase;
import com.appirio.tech.core.api.v3.util.jdbi.TCBeanMapperFactory;
import com.appirio.tech.core.service.identity.representation.Group;
import com.appirio.tech.core.service.identity.representation.GroupMembership;
import com.appirio.tech.core.service.identity.util.Utils;

/**
 * DAO used to manage group.
 *
 * <p>
 * Version 1.1 - GROUP AND MEMBERSHIP MANAGEMENT API
 * - Added {@link #update(Group)}, {@link #delete(TCID)}, {@link #updateGroup(Group)}, {@link #deleteGroup(long)}
 *   and {@link #findMembershipsByGroup(long)} methods
 * - Fixed a bug in {@link #findMembership(long)} method which did not populate groupId, memberId and membershipType
 * </p>
 *
 * <p>
 * Version 1.2 - GROUPS API ENHANCEMENTS
 * - Updated SQL queries to account for "privateGroup" and "selfRegister" fields
 * - Added membershipExists and findMembershipByGroupAndMember methods
 * </p>
 *
 * <p>
 * Changes in the version 1.3 in TC Identity Service - Groups API Return All Sub-groups v1.0
 * - add findSubGroups method
 * </p>
 * 
 * <p>
 * Changes in the version 1.4 72h TC Identity Service API Enhancements v1.0
 * - add method to get member count for groups
 * - modified findMembershipByGroupAndMember to retrieve fields for member ship
 * </p>
 *
 * @author TCSCODER
 * @version 1.4
 */
@UseStringTemplate3StatementLocator
@RegisterMapperFactory(TCBeanMapperFactory.class)
public abstract class GroupDAO implements DaoBase<Group>, Transactional<GroupDAO> {

	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlQuery(
			"SELECT id, name, description, private_group AS privateGroup, self_register AS selfRegister, createdBy, createdAt, modifiedBy, modifiedAt " +
			"FROM `group` WHERE id = :id"
	)
	public abstract Group findGroupById(@Bind("id") long id);

	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlQuery(
			"SELECT id, name, description, private_group AS privateGroup, self_register AS selfRegister, createdBy, createdAt, modifiedBy, modifiedAt " +
			"FROM `group` WHERE name = :name"
	)
	public abstract Group findGroupByName(@Bind("name") String name);

	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlQuery(
			"SELECT id, name, description, private_group AS privateGroup, self_register AS selfRegister, createdBy, createdAt, modifiedBy, modifiedAt " +
			"FROM `group` ORDER BY id"
	)
	public abstract List<Group> findAllGroups();

	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlQuery(
			"SELECT g.id, g.name, g.description, g.private_group AS privateGroup, g.self_register AS selfRegister, g.createdBy, g.createdAt, g.modifiedBy, g.modifiedAt " +
			"FROM `group` AS g INNER JOIN group_membership AS gm ON g.id = gm.group_id " +
			"WHERE gm.member_id = :memberId and gm.membership_type = :type ORDER BY g.id"
	)
	abstract List<Group> findGroupsByMember(@Bind("memberId") long memberId, @Bind("type") int type);

	/**
         * Get sub groups for a parent group
         *
         * @param parentGroupId the parent group id
         * @return a list of sub groups
	 */
	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlQuery("SELECT g.id, g.name, g.description, g.createdBy, g.createdAt, g.modifiedBy, g.modifiedAt "
            + "FROM `group` AS g INNER JOIN group_membership AS gm ON g.id = gm.member_id "
            + "WHERE gm.group_id = :groupId and gm.membership_type = 2 ORDER BY g.id")
	public abstract List<Group> findSubGroups(@Bind("groupId") long parentGroupId);

	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlUpdate("INSERT INTO `group`("
			+ "name, description, private_group, self_register, createdBy, createdAt, modifiedBy, modifiedAt"
			+ ") VALUES ("
			+ ":g.name, :g.description, :g.privateGroup, :g.selfRegister, :g.createdBy, :g.createdAt, :g.modifiedBy, :g.modifiedAt)")
	@GetGeneratedKeys
	abstract int createGroup(@BindBean("g") Group group);

	/**
	 * Find membership by id.
	 * <p>
	 * Version 1.1 - GROUP AND MEMBERSHIP MANAGEMENT API
	 * - Fixed bug which did not populate groupId, memberId and membershipType
	 * </p>
	 * @param id the membership id
	 * @return membership
	 */
	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlQuery(
			"SELECT id, group_id AS groupId, member_id AS memberId, membership_type AS membershipTypeId, " +
			"createdBy, createdAt, modifiedBy, modifiedAt " +
			"FROM group_membership WHERE id = :id"
	)
	public abstract GroupMembership findMembership(@Bind("id") long id);

	/**
     * Find membership by group and member
     *
     * @param groupId the groupId to use
     * @param memberId the memberId to use
     * @return the GroupMembership result
     */
	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlQuery(
	        "SELECT group_membership.id, group_id AS groupId, member_id AS memberId, membership_type AS membershipTypeId, " +
	        "group_membership.createdBy, group_membership.createdAt, group_membership.modifiedBy, group_membership.modifiedAt, g.name as groupName " + 
	        "FROM group_membership INNER JOIN `group` as g on g.id = group_membership.group_id WHERE group_id = :groupId AND member_id = :memberId"
	)
    public abstract GroupMembership findMembershipByGroupAndMember(@Bind("groupId") long groupId, @Bind("memberId") long memberId);

	/**
     * Get group member count
     *
     * @param groupIds the groupIds to use
     * @param memberType the memberType to use
     * @return the member count result
     */
	@RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT count(member_id) FROM group_membership WHERE group_id in (<groupIds>) AND membership_type = :memberType")
	public abstract int getMemberCount(@BindIn("groupIds") List<Long> groupIds,  @Bind("memberType") long memberType);

	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlUpdate("INSERT INTO group_membership ("
			+ "group_id, member_id, membership_type, createdBy, createdAt, modifiedBy, modifiedAt"
			+ ") VALUES ("
			+ ":gm.groupId, :gm.memberId, :gm.membershipTypeId, :gm.createdBy, :gm.createdAt, :gm.modifiedBy, :gm.modifiedAt)")
	@GetGeneratedKeys
	abstract int createMembership(@BindBean("gm") GroupMembership membership);

	@SqlUpdate("DELETE FROM group_membership WHERE id = :membershipId")
	abstract int deleteMembership(@Bind("membershipId") long membershipId);

	/**
	 * Delete memberships by group id.
	 * @param groupId the group id
	 * @return delete result
	 * @since 1.1
	 */
	@SqlUpdate("DELETE FROM group_membership WHERE group_id = :groupId")
	abstract int deleteMembershipsOfGroup(@Bind("groupId") long groupId);

	/**
	 * Find members by group id.
	 * @param groupId the group id
	 * @return list of members
	 * @since 1.1
	 */
	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlQuery(
			"SELECT id, group_id AS groupId, member_id AS memberId, membership_type AS membershipTypeId, " +
			"createdBy, createdAt, modifiedBy, modifiedAt " +
			"FROM group_membership WHERE group_id = :groupId ORDER BY id"
	)
	public abstract List<GroupMembership> findMembershipsByGroup(@Bind("groupId") long groupId);

	/**
	 * Checks if a user is a member of a group.
	 * @param groupId the group id
	 * @return list of members
	 * @since 1.1
	 */
	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlQuery(
			"SELECT count(*) FROM group_membership WHERE group_id = :groupId AND member_id = :memberId"
	)
	public abstract int checkMemberOfGroup(@Bind("memberId") long memberId, @Bind("groupId") long groupId);

	/**
	 * Update group.
	 * @param group the group to update
	 * @return update result
	 * @since 1.1
	 */
	@SqlUpdate(
		"UPDATE `group` SET " +
		"name = :g.name, description = :g.description, private_group = :g.privateGroup, self_register = :g.selfRegister, " +
		"modifiedBy = :g.modifiedBy, modifiedAt = :g.modifiedAt WHERE id = :g.id"
	)
	abstract int updateGroup(@BindBean("g") Group group);

	/**
	 * Delete group.
	 * @param groupId the group id
	 * @return delete result
	 * @since 1.1
	 */
	@SqlUpdate("DELETE FROM `group` WHERE id = :groupId")
	abstract int deleteGroup(@Bind("groupId") long groupId);

	public List<Group> findGroupsByUser(long userId) {
		return findGroupsByMember(userId, 1);
	}

	public List<Group> findParentGroups(long groupId) {
		return findGroupsByMember(groupId, 2);
	}

	public List<Group> findGroupsByMember(long memberId, MembershipType membershipType) {
		if(membershipType==null)
			throw new IllegalArgumentException("membershipType must be specified.");
		return findGroupsByMember(memberId, membershipType.id);
	}

	@Transaction(TransactionIsolationLevel.READ_COMMITTED)
	public Group create(Group group) {
		if(group==null)
			throw new IllegalArgumentException("group must be specified.");

		long id = createGroup(group);
		group.setId(new TCID(id));
		return group;
	}

	@Transaction(TransactionIsolationLevel.READ_COMMITTED)
	public GroupMembership addMembership(GroupMembership membership) {
		if(membership==null)
			throw new IllegalArgumentException("membership must be specified.");

		long id = createMembership(membership);
		membership.setId(new TCID(id));
		return membership;
	}

	@Transaction(TransactionIsolationLevel.READ_COMMITTED)
	public int removeMembership(long membershipId) {
		return deleteMembership(membershipId);
	}

	/**
	 * Delete a group.
	 * @param groupId the group id
	 * @throws IllegalArgumentException if given group id is invalid
	 * @since 1.1
	 */
	@Override
	@Transaction(TransactionIsolationLevel.READ_COMMITTED)
	public void delete(TCID groupId) {
		if(!Utils.isValid(groupId))
			throw new IllegalArgumentException("groupId is invalid.");
		long id = Utils.toLongValue(groupId);
		deleteMembershipsOfGroup(id);
		deleteGroup(id);
	}

	/**
	 * Update group.
	 * @param group the group to update
	 * @return group id
	 * @throws IllegalArgumentException if given group is null
	 * @since 1.1
	 */
	@Override
	@Transaction(TransactionIsolationLevel.READ_COMMITTED)
	public TCID update(Group group) {
		if(group==null)
			throw new IllegalArgumentException("group must be specified.");
		updateGroup(group);
		return group.getId();
	}

	public boolean groupExists(String name) {
		if(Utils.isEmpty(name))
			throw new IllegalArgumentException("name must be specified.");

		Group group = findGroupByName(name);
		return group!=null;
	}

	/**
	 * Checks if a membership exists
	 * @param groupId The group id
	 * @param memberId The member id
	 * @return true if the membership exists, false otherwise
	 * @since 1.1
	 */
	public boolean membershipExists(Long groupId, Long memberId) {
		GroupMembership groupMembership = findMembershipByGroupAndMember(groupId, memberId);
		return groupMembership!=null;
	}
}
