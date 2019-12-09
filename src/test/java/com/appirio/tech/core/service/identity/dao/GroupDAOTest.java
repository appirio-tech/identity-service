/**
 * Copyright (C) 2017 Topcoder Inc., All Rights Reserved.
 */
package com.appirio.tech.core.service.identity.dao;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.List;

import org.joda.time.DateTime;
import org.junit.Test;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.service.identity.representation.Group;
import com.appirio.tech.core.service.identity.representation.GroupMembership;
import com.appirio.tech.core.service.identity.representation.GroupMembership.MembershipType;

/**
 * Unit tests for {@link GroupDAO}.
 * 
 * <p>
 * Version 1.1 - GROUP AND MEMBERSHIP MANAGEMENT API
 * - Added unit tests for {@link GroupDAO#update(Group)} and {@link GroupDAO#delete(TCID)} 
 * </p>
 *
 * @author TCSCODER
 * @version 1.1
 */
@SuppressWarnings("serial")
public class GroupDAOTest {
	
	@Test
	public void testCreate_OK() {
		
		// test data
		int newId = 123;
		Group group = createGroup("TestGroup", "This is a test group.");
		
		// testee
		GroupDAO testee = mock(GroupDAO.class);
		doReturn(newId).when(testee).createGroup(group);
		doCallRealMethod().when(testee).create(any(Group.class));
		
		// test
		Group result = testee.create(group);
		
		// checking result
		assertNotNull("The result object should not be null.", result);
		assertNotNull("The result object should have an ID.", result.getId());
		assertEquals(newId, Integer.parseInt(result.getId().getId()));
		assertEquals(group.getName(), result.getName());
		assertEquals(group.getDescription(), result.getDescription());
		
		verify(testee).create(group);		
	}

	@Test
	public void testCreate_ERR_WhenGroupIsNull() {		
		// testee
		GroupDAO testee = mock(GroupDAO.class);
		doCallRealMethod().when(testee).create(any(Group.class));
		
		// test
		try {
			testee.create(null);
			fail("An exception should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
		
		// checking result
		verify(testee, never()).createGroup(any(Group.class));		
	}
	
	@Test
	public void testFindGroupsByMember_OK() {
		
		// test data
		Group group = createGroup(new TCID(123), "TestGroup", "This is a test group.", null, null, null, null);
		List<Group> groups = new ArrayList<Group>(1) {{ add(group); }};
		long memberId = 456L;
		
		// testee
		GroupDAO testee = mock(GroupDAO.class);
		doReturn(groups).when(testee).findGroupsByMember(memberId, MembershipType.User.id);
		doCallRealMethod().when(testee).findGroupsByMember(anyLong(), any(MembershipType.class));
		
		// test
		List<Group> result = testee.findGroupsByMember(memberId, MembershipType.User);
		
		// checking result
		assertNotNull("The result object should not be null.", result);
		assertEquals(groups.size(), result.size());
		
		verify(testee).findGroupsByMember(memberId, MembershipType.User.id);
	}
	
	@Test
	public void testFindGroupsByMember_ERR_WhenMembershipTypeIsNull() {
		// testee
		GroupDAO testee = mock(GroupDAO.class);
		doCallRealMethod().when(testee).findGroupsByMember(anyLong(), any(MembershipType.class));
		
		// test
		try {
			testee.findGroupsByMember(456L, null);
			fail("An exception should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
		
		// checking result
		verify(testee, never()).findGroupsByMember(anyLong(), anyInt());	
	}
	
	@Test
	public void testAddMembership_OK() {
		// data
		int newId = 123;
		GroupMembership membership = new GroupMembership();
		membership.setGroupId(345L);
		membership.setMemberId(789L);
		membership.setMembershipTypeId(MembershipType.User.id);
		
		// testee
		GroupDAO testee = mock(GroupDAO.class);
		doReturn(newId).when(testee).createMembership(membership);
		doCallRealMethod().when(testee).addMembership(any(GroupMembership.class));

		// test
		GroupMembership result = testee.addMembership(membership);
		
		// checking result
		assertNotNull("The result object should not be null.", result);
		assertNotNull("The result object should have an ID.", result.getId());
		assertEquals(newId, Integer.parseInt(result.getId().getId()));
		assertEquals(membership.getGroupId(), result.getGroupId());
		assertEquals(membership.getMemberId(), result.getMemberId());
		assertEquals(membership.getMembershipTypeId(), result.getMembershipTypeId());

		verify(testee).createMembership(membership);
	}
	
	@Test
	public void testAddMembership_ERR_WhenMembershipIsNull() {
		// testee
		GroupDAO testee = mock(GroupDAO.class);
		doCallRealMethod().when(testee).addMembership(any(GroupMembership.class));
		
		// test
		try {
			testee.addMembership(null);
			fail("An exception should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
		
		// checking result
		verify(testee, never()).createMembership(any(GroupMembership.class));
	}

	@Test
	public void testGroupExists_OK_WithExistentGroup() {
		testGroupExists_OK_With(GROUP_EXISTS);
	}
	
	@Test
	public void testGroupExists_OK_WithNonExistentGroup() {
		testGroupExists_OK_With(GROUP_NOT_EXIST);
	}
	
	static boolean GROUP_EXISTS = true;
	static boolean GROUP_NOT_EXIST = false;
	public void testGroupExists_OK_With(boolean groupExists) {
		// data
		String groupName = "TestGroup";
		Group group = groupExists ? createGroup(groupName, null) : null;
		
		// testee
		GroupDAO testee = mock(GroupDAO.class);
		doReturn(group).when(testee).findGroupByName(groupName);
		doCallRealMethod().when(testee).groupExists(groupName);
		
		// test
		boolean result = testee.groupExists(groupName);
		
		// checking result
		assertEquals(groupExists, result);
		
		verify(testee).findGroupByName(groupName);
	}

	@Test
	public void testGroupExists_ERR_WhenGroupNameIsNull() {
		// testee
		GroupDAO testee = mock(GroupDAO.class);
		doCallRealMethod().when(testee).groupExists(any());
		
		// test
		try {
			testee.groupExists(null);
			fail("An exception should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
		
		// checking result
		verify(testee, never()).findGroupByName(anyString());
	}

	/**
	 * Test {@link GroupDAO#update(Group)} method.
	 */
	@Test
	public void testUpdateGroup_OK() {

		// test data
		int newId = 123;
		Group group = createGroup("TestGroup", "This is a test group.");
		group.setId(new TCID(newId));
		
		// testee
		GroupDAO testee = mock(GroupDAO.class);
		doReturn(1).when(testee).updateGroup(group);
		doCallRealMethod().when(testee).update(any(Group.class));
		
		// test
		TCID result = testee.update(group);
		
		// checking result
		assertNotNull("The result object should not be null.", result);
		assertNotNull("The result object should have an ID.", result.getId());
		assertEquals(newId, Integer.parseInt(result.getId()));
		
		verify(testee).update(group);   
	}

	/**
	 * Test {@link GroupDAO#update(Group)} method.
	 * IllegalArgumentException should be raised when group is null.
	 */
	@Test
	public void testUpdateGroup_ERR_WhenGroupIsNull() {	  
		// testee
		GroupDAO testee = mock(GroupDAO.class);
		doCallRealMethod().when(testee).update(any(Group.class));
		
		// test
		try {
			testee.update(null);
			fail("An exception should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
		
		// checking result
		verify(testee, never()).updateGroup(any(Group.class));	  
	}

	/**
	 * Test {@link GroupDAO#delete(TCID)} method.
	 */
	@Test
	public void testDeleteGroup_OK() {

		// test data
		long newId = 123;
		TCID groupId = new TCID(newId);

		// testee
		GroupDAO testee = mock(GroupDAO.class);
		doReturn(1).when(testee).deleteGroup(newId);
		doCallRealMethod().when(testee).delete(any(TCID.class));
		
		// test
		testee.delete(groupId);
		
		// checking result
		
		verify(testee).deleteGroup(newId);   
	}

	/**
	 * Test {@link GroupDAO#delete(TCID)} method.
	 * IllegalArgumentException should be raised when group id is null.
	 */
	@Test
	public void testDeleteGroup_ERR_WhenGroupIdIsNull() {

		// testee
		GroupDAO testee = mock(GroupDAO.class);
		doCallRealMethod().when(testee).delete(any(TCID.class));
		
		// test
		try {
			testee.delete(null);
			fail("An exception should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
		
		// checking result
		verify(testee, never()).deleteGroup(any(Long.class)); 
	}

	/**
	 * Test {@link GroupDAO#delete(TCID)} method.
	 * IllegalArgumentException should be raised when group id is invalid.
	 */
	@Test
	public void testDeleteGroup_ERR_WhenGroupIdIsInvalid() {

		TCID groupId = new TCID("invalid_id");

		// testee
		GroupDAO testee = mock(GroupDAO.class);
		doCallRealMethod().when(testee).delete(any(TCID.class));
		
		// test
		try {
			testee.delete(groupId);
			fail("An exception should be thrown in the previous step.");
		} catch (IllegalArgumentException e) {
		}
		
		// checking result
		verify(testee, never()).deleteGroup(any(Long.class)); 
	}

	Group createGroup(TCID id, String name, String desc, TCID createdBy, DateTime createdAt, TCID modifiedBy, DateTime modifiedAt) {
		Group group = new Group();
		group.setId(id);
		group.setName(name);
		group.setDescription(desc);
		group.setCreatedBy(createdBy);
		group.setCreatedAt(createdAt);
		group.setModifiedBy(modifiedBy);
		group.setModifiedAt(modifiedAt);
		return group;
	}
	
	Group createGroup(String name, String desc) {
		return createGroup(null, name, desc, null, null, null, null);
	}
}
