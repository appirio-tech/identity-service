package com.appirio.tech.core.service.identity.resource;

import java.util.List;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.log4j.Logger;

import com.appirio.tech.core.api.v3.request.FieldSelector;
import com.appirio.tech.core.api.v3.request.annotation.APIFieldParam;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.api.v3.response.ApiResponseFactory;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.dao.SSOLoginProviderDAO;
import com.appirio.tech.core.service.identity.representation.SSOLoginProvider;
import com.codahale.metrics.annotation.Timed;

/**
 * Resource for sso login provider
 * 
 * 
 * @author TCCoder
 * @version 1.0
 *
 */
@Path("ssoLoginProviders")
@Produces(MediaType.APPLICATION_JSON)
public class SSOLoginProviderResource {
    /**
     * The logger attribute.
     */
    private static final Logger logger = Logger.getLogger(SSOLoginProviderResource.class);
    
    /**
     * The sso login providerdao attribute.
     */
    private final SSOLoginProviderDAO ssoLoginProviderDAO;

    /**
     * Create SSOLoginProviderResource
     *
     * @param ssoLoginProviderDAO the ssoLoginProviderDAO to use
     */
    public SSOLoginProviderResource(SSOLoginProviderDAO ssoLoginProviderDAO) {
        this.ssoLoginProviderDAO = ssoLoginProviderDAO;
    }

    /**
     * Get all providers
     *
     * @param authUser the authUser to use
     * @param selector the selector to use
     * @return the ApiResponse result
     */
    @GET
    @Timed
    public ApiResponse getAllProviders(AuthUser authUser, @APIFieldParam(repClass = SSOLoginProvider.class) FieldSelector selector) {
        logger.debug("getAllProviders()");
        
        List<SSOLoginProvider> providers = this.ssoLoginProviderDAO.getAllProviders();
        
        return ApiResponseFactory.createFieldSelectorResponse(providers, selector);
    }

}
