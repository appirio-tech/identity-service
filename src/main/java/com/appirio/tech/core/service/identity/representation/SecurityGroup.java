package com.appirio.tech.core.service.identity.representation;

import com.appirio.tech.core.api.v3.resource.old.RESTResource;

/**
 * SecurityGroup entity
 * 
 * It's added in  72h TC Identity Service API Enhancements v1.0
 * 
 * @author TCCoder
 * @version 1.0
 *
 */
public class SecurityGroup implements RESTResource {
    
    /**
     * Represents the id attribute.
     */
    private long id;
    
    /**
     * Represents the name attribute.
     */
    private String name;
    
    /**
     * Represents the createUserId attribute.
     */
    private Long createUserId;


    /**
     * Get id.
     * @return the id. 
     */
    public long getId() {
        return this.id;
    }
    
    /**
     * Set id.
     * @return the id to set. 
     */
    public void setId(long id) {
        this.id = id;
    }

    /**
     * Get name.
     * @return the name. 
     */
    public String getName() {
        return this.name;
    }
    
    /**
     * Set name.
     * @return the name to set. 
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get createUserId.
     * @return the createUserId. 
     */
    public Long getCreateUserId() {
        return this.createUserId;
    }
    
    /**
     * Set createUserId.
     * @return the createUserId to set. 
     */
    public void setCreateUserId(Long createUserId) {
        this.createUserId = createUserId;
    }
}
