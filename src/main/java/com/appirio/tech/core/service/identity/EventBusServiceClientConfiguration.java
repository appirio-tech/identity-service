package com.appirio.tech.core.service.identity;

import org.hibernate.validator.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The EventBusServiceClientConfiguration is for configuration.
 * 
 * It's add in Fast 48hrs!! Topcoder Identity Service - Support Event Bus Publishing v1.0
 * 
 * @author TCCoder
 * @version 1.0
 */
public class EventBusServiceClientConfiguration {
    /**
     * Represents the endpoint attribute.
     */
    @JsonProperty
    @NotEmpty
    private String endpoint;


    /**
     * Represents the topic attribute.
     */
    @JsonProperty
    @NotEmpty
    private String topic;


    /**
     * Represents the originator attribute.
     */
    @JsonProperty
    @NotEmpty
    private String originator;

    /**
     * Get originator
     * 
     * @return the originator
     */
    public String getOriginator() {
        return this.originator;
    }

    /**
     * Set originator
     * 
     * @return the originator to set
     */
    public void setOriginator(String originator) {
        this.originator = originator;
    }

    /**
     * Get topic
     * 
     * @return the topic
     */
    public String getTopic() {
        return this.topic;
    }

    /**
     * Set topic
     * 
     * @return the topic to set
     */
    public void setTopic(String topic) {
        this.topic = topic;
    }

    /**
     * Get endpoint
     * 
     * @return the endpoint
     */
    public String getEndpoint() {
        return this.endpoint;
    }

    /**
     * Set endpoint
     * 
     * @return the endpoint to set
     */
    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }
}