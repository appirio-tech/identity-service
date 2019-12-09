/**
 * Copyright (C) 2017 Topcoder Inc., All Rights Reserved.
 */
package com.appirio.tech.core.service.identity.resource;

import static org.junit.Assert.*;
import static org.mockito.Mockito.spy;

import java.util.LinkedList;
import java.util.List;


import org.joda.time.DateTime;
import org.junit.Test;

import com.appirio.tech.core.api.v3.ApiVersion;
import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.service.identity.dao.GroupDAO;
import com.appirio.tech.core.service.identity.representation.Group;
import com.appirio.tech.core.service.identity.representation.GroupMembership;
import com.appirio.tech.core.service.identity.representation.GroupMembership.MembershipType;

/**
 * Base class for resource test classes.
 *
 * <p>
 * Version 1.1 - GROUPS API ENHANCEMENTS
 * - Set privateGroup and selfRegister fields when creating group
 * </p>
 *
 * @author TCSCODER
 * @version 1.1
 */
public class GroupResourceTestBase {

	@Test
	public void test() {
		assertTrue("This always pass.", true);
	}

	public void failWhenExpectedExceptionNotThrown() {
		fail("An exception should be thrown in the previous step.");
	}

	public void checkApiResponseHeader(ApiResponse result, int status) {
		assertEquals(ApiVersion.v3, result.getVersion());
		assertNotNull(result.getResult());
		assertEquals(status, (int)result.getResult().getStatus());
		assertTrue("ApiResponse.Result should be success.", result.getResult().getSuccess());
	}

	GroupResource createGroupResourceMock(GroupDAO groupDao) {
		GroupResource resource = spy(new GroupResource(groupDao, null));
		return resource;
	}

	/**
	 * Creates a group
	 * @param id The group id
	 * @param name The group name
	 * @param desc The group description
	 * @param createdBy The id of the user that creates the group
	 * @param createdAt The date the group is created
	 * @param modifiedBy The id of the user that modifies the group
	 * @param modifiedAt The date the group is modified
	 * @return The created group
	 * @since 1.1
	 */
	Group createGroup(TCID id, String name, String desc, TCID createdBy, DateTime createdAt, TCID modifiedBy, DateTime modifiedAt) {
		Group group = new Group();
		group.setId(id);
		group.setName(name);
		group.setDescription(desc);
		group.setPrivateGroup(true);
		group.setSelfRegister(false);
		group.setCreatedBy(createdBy);
		group.setCreatedAt(createdAt);
		group.setModifiedBy(modifiedBy);
		group.setModifiedAt(modifiedAt);
		return group;
	}

	Group createGroup(String name, String desc) {
		return createGroup(null, name, desc, null, null, null, null);
	}

	List<Group> createSimpleGroups(int count) {
		// data
		List<Group> groups = new LinkedList<>();
		for(int i=0; i<count; i++) {
			int n = i+1;
			groups.add(createGroup("TestGroup"+n, "Test Group "+n));
		}
		return groups;
	}

	/**
	 * Create member.
	 *
	 * @param groupId the group id
	 * @return the member
	 */
	protected GroupMembership createGroupMembership(long groupId, long memberId) {
		GroupMembership member = new GroupMembership();
		member.setId(new TCID(1));
		member.setGroupId(groupId);
		member.setMemberId(memberId);
		member.setMembershipType(MembershipType.User.lowerName());
		member.setCreatedAt(DateTime.now());
		member.setCreatedBy(new TCID(111));
		return member;
	}
}
