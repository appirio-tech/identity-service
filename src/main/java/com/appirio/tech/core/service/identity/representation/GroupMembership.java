package com.appirio.tech.core.service.identity.representation;

import com.appirio.tech.core.api.v3.model.AbstractIdResource;
import com.appirio.tech.core.service.identity.util.Utils;
import com.fasterxml.jackson.annotation.JsonIgnore;

public class GroupMembership extends AbstractIdResource {
	
	private Long groupId;
	
	private String groupName;
	
	private Long memberId;
		
	private String membershipType;

	public Long getGroupId() {
		return groupId;
	}

	public void setGroupId(Long groupId) {
		this.groupId = groupId;
	}

	public String getGroupName() {
		return groupName;
	}

	public void setGroupName(String groupName) {
		this.groupName = groupName;
	}

	public Long getMemberId() {
		return memberId;
	}

	public void setMemberId(Long memberId) {
		this.memberId = memberId;
	}

	public String getMembershipType() {
		return this.membershipType;
	}

	public void setMembershipType(String membershipType) {
		this.membershipType = membershipType;
	}

	@JsonIgnore
	public Integer getMembershipTypeId() {
		MembershipType mt = MembershipType.get(this.membershipType);
		return mt!=null ? mt.id : null;
	}

	@JsonIgnore
	public void setMembershipTypeId(Integer membershipTypeId) {
		MembershipType mt = MembershipType.get(membershipTypeId);
		this.membershipType = mt!=null ? mt.name().toLowerCase() : null;
	}
	
	public static enum MembershipType {
		User(1),
		Group(2);
		
		MembershipType(int id) {
			this.id = id;
		}
		public int id;
		
		public String lowerName() {
			return name().toLowerCase();
		}
		
		public static MembershipType get(int id) {
			for(MembershipType type : MembershipType.values()) {
				if(type.id == id)
					return type;
			}
			return null;
		}
		public static MembershipType get(String key) {
			if(Utils.isEmpty(key))
				return null;
			for(MembershipType type : MembershipType.values()) {
				if(type.name().equalsIgnoreCase(key))
					return type;
			}
			return null;			
		}
	}
}
