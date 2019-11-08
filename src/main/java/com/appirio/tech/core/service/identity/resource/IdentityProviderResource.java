package com.appirio.tech.core.service.identity.resource;

import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.request.FilterParameter;
import com.appirio.tech.core.api.v3.request.QueryParameter;
import com.appirio.tech.core.api.v3.request.annotation.APIQueryParam;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.api.v3.response.ApiResponseFactory;
import com.appirio.tech.core.service.identity.dao.IdentityProviderDAO;
import com.appirio.tech.core.service.identity.representation.IdentityProvider;
import com.codahale.metrics.annotation.Timed;
import org.apache.log4j.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * Created by ramakrishnapemmaraju on 12/1/15.
 */
@Path("identityproviders")
@Produces(MediaType.APPLICATION_JSON)
public class IdentityProviderResource {

    private static final Logger logger = Logger.getLogger(IdentityProviderResource.class);

    protected IdentityProviderDAO dao;

    public IdentityProviderResource(IdentityProviderDAO dao) {
        this.dao = dao;
    }

    /**
     * Return Identity Provider of a user
     */
    @GET
    @Timed
    public ApiResponse fetchProviderInfo(
            @APIQueryParam(repClass = IdentityProvider.class) QueryParameter query,
            @Context HttpServletRequest request) throws Exception {

        logger.info("fetchProviderInfo");

        FilterParameter filter = query.getFilter();
        String handle = null;
        if (filter.get("handle") != null) {
            handle = (String) filter.get("handle");
            logger.info("handle: "+handle);
        }
        String email = null;
        if (filter.get("email") != null) {
            email = (String) filter.get("email");
            logger.info("email: "+email);
        }

        if (handle == null && email == null)
            throw new APIRuntimeException(HttpServletResponse.SC_BAD_REQUEST, "handle or email required");

        IdentityProvider identityProvider = null;

        // try with userName
        if(handle != null) {
            // try to look into SSO providers by SSO userId
            identityProvider = dao.getSSOProviderByUserId(handle);
            if(identityProvider==null) {
                // try to look into SSO providers by SSO email
            	identityProvider = dao.getSSOProviderByEmail(handle);
            }
            if(identityProvider==null) {
                // try to look into SSO providers by TC handle
            	identityProvider = dao.getSSOProviderByHandle(handle);
            }
            if(identityProvider==null) {
                // try to look into Social providers by Social userId
            	identityProvider = dao.getSocialProviderByUserId(handle);
            }
        } else if(email != null) {
            identityProvider = dao.getSocialProviderByUserEmail(email);
        }
        if(identityProvider==null) {
        	identityProvider = createDefaultProvider();
        }
        return ApiResponseFactory.createResponse(identityProvider);
    }

	protected IdentityProvider createDefaultProvider() {
		IdentityProvider identityProvider = new IdentityProvider();
		identityProvider.setName("ldap");
		identityProvider.setType("default");
		return identityProvider;
	}
}
