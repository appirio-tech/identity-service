package com.appirio.tech.core.service.identity.representation;

import com.appirio.tech.core.api.v3.resource.old.RESTResource;

/**
 * Represents the SSOLoginProvider model
 * 
 * 
 * @author TCCoder
 * @version 1.0
 *
 */
public class SSOLoginProvider implements RESTResource {

    /**
     * Represents the ssoLoginProviderId attribute
     */
    private long ssoLoginProviderId;


    /**
     * Represents the name attribute
     */
    private String name;


    /**
     * Represents the type attribute.
     */
    private String type;

    /**
     * Get ssoLoginProviderId
     * 
     * @return the ssoLoginProviderId
     */
    public long getSsoLoginProviderId() {
        return this.ssoLoginProviderId;
    }

    /**
     * Set ssoLoginProviderId
     * 
     * @return the ssoLoginProviderId to set
     */
    public void setSsoLoginProviderId(long ssoLoginProviderId) {
        this.ssoLoginProviderId = ssoLoginProviderId;
    }

    /**
     * Get name
     * 
     * @return the name
     */
    public String getName() {
        return this.name;
    }

    /**
     * Set name
     * 
     * @return the name to set
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get type
     * 
     * @return the type
     */
    public String getType() {
        return this.type;
    }

    /**
     * Set type
     * 
     * @return the type to set
     */
    public void setType(String type) {
        this.type = type;
    }
}
