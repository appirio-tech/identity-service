/**
* Copyright (C) 2017 Topcoder Inc., All Rights Reserved.
*/
package com.appirio.tech.core.service.identity.representation;

import java.util.List;

import com.appirio.tech.core.api.v3.model.AbstractIdResource;

/**
 * The group entity.
 *
 * Changes in the version 1.1 in TC Identity Service - Groups API Return All
 * Sub-groups v1.0 - add subGroups field
 *
 * @author TCCoder
 * @version 1.1
 *
 */
public class Group extends AbstractIdResource {

    /**
     * The group name
     */
    private String name;


    /**
     * The group description
     */
    private String description;


    /**
     * Flag indicating if the group is private
     */
    private Boolean privateGroup;


    /**
     * Flag indicating if a non-admin user can self register to the group
     */
    private Boolean selfRegister;


    /**
     * Represents the subGroups attribute.
     */
    private List<Group> subGroups;
    
    /**
     * Represents the parentGroup attribute.
     */
    private Group parentGroup;

    /**
     * Retrieves the group name
     * 
     * @return The group name
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the group name
     * 
     * @param name The new group name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Retrieves the group description
     * 
     * @return The group description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets the group description
     * 
     * @param name The new group description
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Retrieves the group privateGroup
     * 
     * @return The group privateGroup
     */
    public Boolean getPrivateGroup() {
        return privateGroup;
    }

    /**
     * Sets the group privateGroup
     * 
     * @param name The new group privateGroup
     */
    public void setPrivateGroup(Boolean privateGroup) {
        this.privateGroup = privateGroup;
    }

    /**
     * Retrieves the group selfRegister
     * 
     * @return The group selfRegister
     */
    public Boolean getSelfRegister() {
        return selfRegister;
    }

    /**
     * Sets the group selfRegister
     * 
     * @param name The new group selfRegister
     */
    public void setSelfRegister(Boolean selfRegister) {
        this.selfRegister = selfRegister;
    }

    /**
     * Get subGroups.
     *
     * @return the subGroups.
     */
    public List<Group> getSubGroups() {
        return this.subGroups;
    }

    /**
     * Set subGroups.
     *
     * @return the subGroups to set.
     */
    public void setSubGroups(List<Group> subGroups) {
        this.subGroups = subGroups;
    }

    /**
     * Get parentGroup.
     * @return the parentGroup. 
     */
    public Group getParentGroup() {
        return this.parentGroup;
    }
    
    /**
     * Set parentGroup.
     * @return the parentGroup to set. 
     */
    public void setParentGroup(Group parentGroup) {
        this.parentGroup = parentGroup;
    }
}
