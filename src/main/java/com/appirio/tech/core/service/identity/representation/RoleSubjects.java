package com.appirio.tech.core.service.identity.representation;

import com.appirio.tech.core.api.v3.model.AbstractIdResource;
import com.appirio.tech.core.api.v3.model.annotation.ApiMapping;

import java.util.List;

/**
 * Role and subject info list
 */
public class RoleSubjects extends AbstractIdResource {
    private String roleName;
    private List<MemberInfo> subjects;

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public List<MemberInfo> getSubjects() {
        return subjects;
    }

    @ApiMapping(queryDefault=false)
    public void setSubjects(List<MemberInfo> subjects) {
        this.subjects = subjects;
    }
}
