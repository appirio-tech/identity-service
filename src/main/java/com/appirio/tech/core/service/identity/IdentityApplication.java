/**
 * 
 */
package com.appirio.tech.core.service.identity;


import io.dropwizard.assets.AssetsBundle;
import io.dropwizard.client.JerseyClientBuilder;
import io.dropwizard.client.JerseyClientConfiguration;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.jackson.Jackson;
import io.dropwizard.jdbi.DBIFactory;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.dropwizard.views.ViewBundle;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.ws.rs.client.Client;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.util.Factory;
import org.skife.jdbi.v2.DBI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.appirio.eventsbus.api.client.EventProducer;
import com.appirio.eventsbus.api.client.exception.ProducerInitializationException;
import com.appirio.tech.core.api.v3.dropwizard.APIApplication;
import com.appirio.tech.core.api.v3.util.jdbi.TCIDArgumentFactory;
import com.appirio.tech.core.service.identity.clients.EventBusServiceClient;
import com.appirio.tech.core.service.identity.dao.ClientDAO;
import com.appirio.tech.core.service.identity.dao.ExternalAccountDAO;
import com.appirio.tech.core.service.identity.dao.GroupDAO;
import com.appirio.tech.core.service.identity.dao.GroupInformixDAO;
import com.appirio.tech.core.service.identity.dao.IdentityProviderDAO;
import com.appirio.tech.core.service.identity.dao.PermissionPolicyDAO;
import com.appirio.tech.core.service.identity.dao.RoleDAO;
import com.appirio.tech.core.service.identity.dao.SSOLoginProviderDAO;
import com.appirio.tech.core.service.identity.dao.UserDAO;
import com.appirio.tech.core.service.identity.resource.AuthorizationResource;
import com.appirio.tech.core.service.identity.resource.GroupResource;
import com.appirio.tech.core.service.identity.resource.IdentityProviderResource;
import com.appirio.tech.core.service.identity.resource.PoliciesResource;
import com.appirio.tech.core.service.identity.resource.RoleResource;
import com.appirio.tech.core.service.identity.resource.SSOLoginProviderResource;
import com.appirio.tech.core.service.identity.resource.UserResource;
import com.appirio.tech.core.service.identity.util.Utils;
import com.appirio.tech.core.service.identity.util.auth.Auth0Client;
import com.appirio.tech.core.service.identity.util.auth.ServiceAccountAuthenticator;
import com.appirio.tech.core.service.identity.util.cache.CacheService;
import com.appirio.tech.core.service.identity.util.event.EventClientManager;
import com.appirio.tech.core.service.identity.util.ldap.LDAPService;
import com.appirio.tech.core.service.identity.util.shiro.Shiro;
import com.appirio.tech.core.service.identity.util.store.AuthDataStore;
import com.appirio.tech.core.service.identity.util.zendesk.ZendeskAuthPlugin;


/**
 * Identity Service Application
 * Created for quick WebFlow authentication
 * 
 * <p>
 * Changes in the version 1.1 72h TC Identity Service API Enhancements v1.0
 * - create the GroupResource with GroupInformixDAO
 * </p>
 * 
 * <p>
 * Version 1.2 - Fast 48hrs!! Topcoder Identity Service - Support Event Bus Publishing v1.0
 * - create the event bus client for UserReource
 * </p>
 * 
 * @author sudo, TCCoder
 * @version 1.2 
 *
 */
public class IdentityApplication extends APIApplication<IdentityConfiguration> {
    /**
     * The PROP_KEY_JWT_SECRET field 
     */
    public static final String PROP_KEY_JWT_SECRET = "TC_JWT_KEY";

    /**
     * The PROP_KEY_VALID_ISSUERS field 
     */
    public static final String PROP_KEY_VALID_ISSUERS = "VALID_ISSUERS";
    
	private static final Logger logger = LoggerFactory.getLogger(IdentityApplication.class);

	/**
     * Get property
     *
     * @param propertyKey the propertyKey to use
     * @return the String result
     */
    private static String getProperty(String propertyKey) {
        String key = System.getenv(propertyKey);
        if (key != null) {
            return key;
        }
        key = System.getProperty(propertyKey);
        if (key == null) {
            logger.warn(propertyKey + " is not found in both of environment variables and system properties.");
        }
        return key;
    }
    
    /**
     * Override the get secret method.
     * @return the secret value
     */
    @Override
    public String getSecret() {
        return getProperty(PROP_KEY_JWT_SECRET);
    }
    /**
     * Override the get valid issues method.
     * @return the issues value
     */
    @Override
    public List<String> getValidIssuers() {
        // Read valid issuers from env
        List<String> validIssuers = null;
        String validIssuersStr = getProperty(PROP_KEY_VALID_ISSUERS);
        if (validIssuersStr != null) {
            validIssuers = Arrays.asList(validIssuersStr.split(","));
        }
        if (validIssuers == null) {
            validIssuers = new ArrayList<>();
        }
        return validIssuers;
    }
    
	@Override
	public void initialize(Bootstrap<IdentityConfiguration> bootstrap) {
		bootstrap.setConfigurationSourceProvider(
				new SubstitutingSourceProvider(bootstrap.getConfigurationSourceProvider(),
                        new EnvironmentVariableSubstitutor(false))
				);
		
		super.initialize(bootstrap);
		/**
		 * Temporary assigning /pub servlet instead of pure html
		 */
		bootstrap.addBundle(new AssetsBundle("/pub", "/pub"));
		bootstrap.addBundle(new ViewBundle());
	}
	
	@Override
	public void run(IdentityConfiguration configuration, Environment environment) throws Exception {
		super.run(configuration, environment);

		// Setup Events
		EventProducer eventProducer;
		try {
			eventProducer = configuration.getEventSystem().getProducerFactory().createProducer();
			EventClientManager eventClientManager = new EventClientManager(eventProducer);
			environment.lifecycle().manage(eventClientManager);
		} catch(ProducerInitializationException e) {
			logger.error("Error in initializing Producer: "+e.getMessage());
			throw e;
		} catch(Exception e) {
			logger.error("Exception: "+e.getMessage());
			throw e;
		}

		// Application context
		Utils.setApplicationContext(configuration.getContext());
		
		// JDBI based DAOs
		final DBIFactory factory = new DBIFactory();
		final DBI jdbi = factory.build(environment, configuration.getDataSourceFactory(), "postgresql");
		jdbi.registerArgumentFactory(new TCIDArgumentFactory());
		final UserDAO userDao = jdbi.onDemand(UserDAO.class);
		final IdentityProviderDAO identityProviderDAO = jdbi.onDemand(IdentityProviderDAO.class);
		
		// LDAP Utility
		LDAPService ldapService = configuration.getLdap().createLDAPService();
		userDao.setLdapService(ldapService);
		
		// DynamoDB based DAO
		AmazonDynamoDBClient dynamoDbClient = new AmazonDynamoDBClient(new DefaultAWSCredentialsProviderChain());
		ExternalAccountDAO externalAccountDao = new ExternalAccountDAO(dynamoDbClient, Jackson.newObjectMapper()); // TODO: how to create object mapper
		userDao.setExternalAccountDao(externalAccountDao);
		
		

		IdentityProviderResource identityProviderResource = new IdentityProviderResource(identityProviderDAO);
		environment.jersey().register(identityProviderResource);

		// RDS
		final DBIFactory authDBIFactory = new DBIFactory();
		final DBI authjdbi = authDBIFactory.build(environment, configuration.getAuthorizationDatabase(), "Authorization");
		authjdbi.registerArgumentFactory(new TCIDArgumentFactory());
		// configure shiro
		Shiro shiroSettings = configuration.getShiroSettings();
		RoleDAO roleDao = null; // RoleDAO for AuthorizationResource
		if(shiroSettings.isUseShiroAuthorization()) {
			Factory<SecurityManager> securityFactory = new IniSecurityManagerFactory(shiroSettings.getIniConfigPath());
			SecurityManager securityManager = securityFactory.getInstance();
			SecurityUtils.setSecurityManager(securityManager);

			// JDBI based DAOs for Authorization
			final RoleDAO roleDAO = authjdbi.onDemand(RoleDAO.class);
			// for AuthorizationResource
			roleDao = authjdbi.onDemand(RoleDAO.class);
			
			roleDAO.setShiroSettings(shiroSettings);

	        // creating new resource for every request
	        RoleResource roleResource = new RoleResource(roleDAO);
	        environment.jersey().register(roleResource);

			final PermissionPolicyDAO policyDAO = authjdbi.onDemand(PermissionPolicyDAO.class);
			policyDAO.setShiroSettings(shiroSettings);
			PoliciesResource polResource = new PoliciesResource(policyDAO, roleDAO);
			environment.jersey().register(polResource);
		}

		final Client apiClient = new JerseyClientBuilder(environment).using(new JerseyClientConfiguration())
                .build(getName());
		final EventBusServiceClient eventBusServiceClient = new EventBusServiceClient(apiClient, 
		        configuration.getEventBusServiceClientConfig(), configuration.getM2mAuthConfiguration());
		// Resources::users
    	CacheService cacheService = configuration.getCache().createCacheService();
    	UserResource userResource = new UserResource(userDao, roleDao, cacheService, eventProducer, eventBusServiceClient, configuration.getM2mAuthConfiguration().getUserProfiles());
    	userResource.setAuth0Client(configuration.getAuth0()); // TODO: constructor
    	userResource.setDomain(configuration.getAuthDomain());
		userResource.setSendgridTemplateId(configuration.getContext().get("sendGridTemplateId"));
    	// this secret _used_ to be different from the one used in AuthorizationResource.
    	// it _was_ the secret x2. (userResource.setSecret(getSecret()+getSecret());)
		// we assume this was done to further limit the usability of the oneTimeToken generated in userResource
		// to accommodate calling the traits and connect2SF services, we're now going to set this the the real secret
		// the exposure is: The user will have a ten minute, user-level token, with no roles, which they can use
		// to call general topcoder API services (minimal exposure)
    	userResource.setSecret(getSecret());
    	environment.jersey().register(userResource);
		final ClientDAO clientDao = authjdbi.onDemand(ClientDAO.class);
		environment.jersey().register(clientDao);
		
		// Resources::groups
		GroupDAO groupDao = authjdbi.onDemand(GroupDAO.class);
		GroupInformixDAO groupInformixDao = jdbi.onDemand(GroupInformixDAO.class);
		GroupResource groupResource = new GroupResource(groupDao, groupInformixDao);
		environment.jersey().register(groupResource);
		environment.jersey().register(groupDao);
		
		// Resources::authorizations
		AuthDataStore authDataStore = configuration.getAuthStore().createAuthDataStore();
		Auth0Client auth0 = configuration.getAuth0();
		Auth0Client auth0New = configuration.getAuth0New();
		ServiceAccountAuthenticator serviceAccountAuthenticator = configuration.getServiceAccount().createServiceAccountAuthenticator();
		ZendeskAuthPlugin zendeskAuthPlugin = configuration.getZendesk().createAuthPlugin();
		AuthorizationResource authResource = new AuthorizationResource(configuration.getAuthDomain(), authDataStore, auth0, auth0New, serviceAccountAuthenticator, userDao, roleDao, cacheService);
		authResource.setJwtExpirySeconds(Utils.getInteger("jwtExpirySeconds", 10 * 60));
		authResource.setCookieExpirySeconds(Utils.getInteger("cookieExpirySeconds", 90 * 24 * 3600));
		authResource.setZendeskAuthPlugin(zendeskAuthPlugin);
		authResource.setClientDao(clientDao);
		authResource.setSecret(getSecret());
		
		environment.jersey().register(authResource);
		
		// register provider resource
		SSOLoginProviderDAO providerDAO = jdbi.onDemand(SSOLoginProviderDAO.class);
		SSOLoginProviderResource providerResource = new SSOLoginProviderResource(providerDAO);
		environment.jersey().register(providerDAO);
		environment.jersey().register(providerResource);
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		new IdentityApplication().run(args);
	}
}
