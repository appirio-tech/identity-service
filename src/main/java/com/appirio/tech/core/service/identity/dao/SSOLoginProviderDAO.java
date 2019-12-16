package com.appirio.tech.core.service.identity.dao;

import java.util.List;

import org.skife.jdbi.v2.sqlobject.SqlQuery;
import org.skife.jdbi.v2.sqlobject.customizers.RegisterMapperFactory;
import org.skife.jdbi.v2.sqlobject.mixins.Transactional;

import com.appirio.tech.core.api.v3.util.jdbi.TCBeanMapperFactory;
import com.appirio.tech.core.service.identity.representation.SSOLoginProvider;

/**
 * SSOLoginProviderDAO is used the query the sso login provider data. 
 * 
 * @author TCCoder
 * @version 1.0
 *
 */
public abstract class SSOLoginProviderDAO implements Transactional<SSOLoginProviderDAO> {

    /**
     * Get all providers
     *
     * @return the List<SSOLoginProvider> result
     */
    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT sso_login_provider_id as ssoLoginProviderId, name, type from common_oltp.sso_login_provider")
    public abstract List<SSOLoginProvider> getAllProviders();
}
