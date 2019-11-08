package com.appirio.tech.core.service.identity;

import io.dropwizard.db.DataSourceFactory;

import java.util.LinkedHashMap;
import java.util.Map;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.appirio.clients.BaseClientConfiguration;
import com.appirio.tech.core.api.v3.dropwizard.APIBaseConfiguration;
import com.appirio.tech.core.service.identity.util.auth.Auth0Client;
import com.appirio.tech.core.service.identity.util.auth.ServiceAccountAuthenticatorFactory;
import com.appirio.tech.core.service.identity.util.cache.CacheServiceFactory;
import com.appirio.tech.core.service.identity.util.event.EventSystemFactory;
import com.appirio.tech.core.service.identity.util.ldap.LDAPServiceFactory;
import com.appirio.tech.core.service.identity.util.shiro.Shiro;
import com.appirio.tech.core.service.identity.util.store.AuthDataStoreFactory;
import com.appirio.tech.core.service.identity.util.zendesk.ZendeskFactory;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The IdentityConfiguration
 * 
 * <p>
 * Changes in the verstion 1.1 (Topcoder - Provide Way to Refresh Auth0 Tokens In authorizations API v1.0)
 * - add auth0New config
 * </p> 
 * 
 * <p>
 * Version 1.2 - Fast 48hrs!! Topcoder Identity Service - Support Event Bus Publishing v1.0
 * - add the m2m and event bus client configuration
 * </p>
 * 
 * @author TCCoder
 * @version 1.2 
 *
 */
public class IdentityConfiguration extends APIBaseConfiguration {

	@Valid
	@JsonProperty
	private CacheServiceFactory cache = new CacheServiceFactory();
	
	@Valid
	@JsonProperty
	private AuthDataStoreFactory authStore = new AuthDataStoreFactory();
	
	@Valid
	@JsonProperty
	private DataSourceFactory database = new DataSourceFactory();

	@Valid
	@JsonProperty
	private Auth0Client auth0 = new Auth0Client();
	
	/**
     * The auth0New field
     */
	@Valid
    @JsonProperty
    private Auth0Client auth0New = new Auth0Client();
	
	@Valid
	@NotNull
	@JsonProperty
	private EventSystemFactory eventSystem = new EventSystemFactory();
	
	@Valid
	@JsonProperty
	private LDAPServiceFactory ldap = new LDAPServiceFactory();
	
	@Valid
	@NotNull
	@JsonProperty
	private Shiro shiroSettings;
	
	@Valid
	@NotNull
	@JsonProperty
	private DataSourceFactory authorizationDatabase = new DataSourceFactory();

	@JsonProperty	
	private ServiceAccountAuthenticatorFactory serviceAccount;
	
	@Valid
	@JsonProperty
	private ZendeskFactory zendesk = new ZendeskFactory();

	@JsonProperty
	private Map<String, Object> context = new LinkedHashMap<String, Object>();
	

    /**
     * The M2mAuthConfiguration config field
     */
    @Valid
    @NotNull
    @JsonProperty("m2mAuthConfig")
    private M2mAuthConfiguration m2mAuthConfig = new M2mAuthConfiguration();


    /**
     * The event bus service client configuration
     */
    @Valid
    @NotNull
    @JsonProperty("eventBusServiceClient")
    private final BaseClientConfiguration eventBusServiceClientConfig = new BaseClientConfiguration();
        
		
	
	public DataSourceFactory getDataSourceFactory() {
		return database;
	}
	
	public CacheServiceFactory getCache() {
		return cache;
	}

	public AuthDataStoreFactory getAuthStore() {
		return authStore;
	}
	
	public Auth0Client getAuth0() {
		return auth0;
	}
	
	/**
     * Get auth0 new
     *
     * @return the Auth0Client result
     */
    public Auth0Client getAuth0New() {
        return auth0New;
    }
	
	public LDAPServiceFactory getLdap() {
		return ldap;
	}
	
	public EventSystemFactory getEventSystem() {
		return eventSystem;
	}

	public Shiro getShiroSettings() {
		return shiroSettings;
	}

	public DataSourceFactory getAuthorizationDatabase() {
		return authorizationDatabase;
	}

	public ServiceAccountAuthenticatorFactory getServiceAccount() {
		return serviceAccount;
	}
	
	public ZendeskFactory getZendesk() {
		return this.zendesk;
	}

	public Map<String, Object> getContext() {
		return context;
	}
	
    /**
     * Get m2m auth configuration
     *
     * @return the M2mAuthConfiguration
     */
    public M2mAuthConfiguration getM2mAuthConfiguration() {
        return this.m2mAuthConfig;
    }

    /**
     * Get eventBusServiceClientConfig
     * 
     * @return the eventBusServiceClientConfig
     */
    public BaseClientConfiguration getEventBusServiceClientConfig() {
        return this.eventBusServiceClientConfig;
    }
}
