package com.appirio.tech.core.service.identity.dao;

import com.appirio.tech.core.api.v3.dao.DaoBase;
import com.appirio.tech.core.api.v3.util.jdbi.TCBeanMapperFactory;
import com.appirio.tech.core.service.identity.representation.IdentityProvider;
import com.appirio.tech.core.service.identity.representation.Role;
import org.apache.log4j.Logger;
import org.skife.jdbi.v2.sqlobject.Bind;
import org.skife.jdbi.v2.sqlobject.SqlQuery;
import org.skife.jdbi.v2.sqlobject.customizers.RegisterMapperFactory;
import org.skife.jdbi.v2.sqlobject.mixins.Transactional;
import org.skife.jdbi.v2.sqlobject.stringtemplate.UseStringTemplate3StatementLocator;

/**
 * Created by ramakrishnapemmaraju on 12/4/15.
 */
@UseStringTemplate3StatementLocator
@RegisterMapperFactory(TCBeanMapperFactory.class)
public abstract class IdentityProviderDAO implements DaoBase<IdentityProvider>, Transactional<IdentityProviderDAO> {

    private static final Logger logger = Logger.getLogger(IdentityProviderDAO.class);

    @SqlQuery(" SELECT "
            + " s.name AS name, "
            + " s.type AS type "
            + " FROM sso_login_provider s "
            + " INNER JOIN "
            + " user_sso_login su "
            + " ON "
            + " su.provider_id = s.sso_login_provider_id "
            + " WHERE "
            + " su.sso_user_id = :userId "
    )
    public abstract IdentityProvider getSSOProviderByUserId(@Bind("userId") String userId);
    
    @SqlQuery(" SELECT "
            + " s.name AS name, "
            + " s.type AS type "
            + " FROM sso_login_provider s "
            + " INNER JOIN "
            + " user_sso_login su "
            + " ON "
            + " su.provider_id = s.sso_login_provider_id "
            + " WHERE "
            + " s.identify_email_enabled = 't' AND "
            + " LOWER(su.email) = LOWER(:email)"
    )
    public abstract IdentityProvider getSSOProviderByEmail(@Bind("email") String email);

    @SqlQuery("SELECT "
            + "s.name AS name, "
            + "s.type AS type "
            + "FROM sso_login_provider s "
            + "INNER JOIN user_sso_login su ON su.provider_id = s.sso_login_provider_id "
            + "INNER JOIN user u ON u.user_id = su.user_id "
            + "WHERE "
            + "s.identify_handle_enabled = 't' AND "
            + "u.handle = :handle"
    )
    public abstract IdentityProvider getSSOProviderByHandle(@Bind("handle") String handle);

    @SqlQuery(" SELECT "
            + " s.name AS name, "
            + " 'social' AS type "
            + " FROM social_login_provider s "
            + " INNER JOIN "
            + " user_social_login su "
            + " ON "
            + " su.social_login_provider_id = s.social_login_provider_id "
            + " WHERE "
            + " su.social_user_name = :userId "
    )
    public abstract IdentityProvider getSocialProviderByUserId(@Bind("userId") String userId);

    @SqlQuery(" SELECT "
            + " s.name AS name, "
            + " 'social' AS type "
            + " FROM social_login_provider s "
            + " INNER JOIN "
            + " user_social_login su "
            + " ON "
            + " su.social_login_provider_id = s.social_login_provider_id "
            + " WHERE "
            + " LOWER(su.social_email) = LOWER(:email) "
    )
    public abstract IdentityProvider getSocialProviderByUserEmail(@Bind("email") String email);

}
