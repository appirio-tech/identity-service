package com.appirio.tech.core.service.identity.dao;

import java.util.List;

import org.apache.log4j.Logger;
import org.skife.jdbi.v2.sqlobject.Bind;
import org.skife.jdbi.v2.sqlobject.BindBean;
import org.skife.jdbi.v2.sqlobject.SqlQuery;
import org.skife.jdbi.v2.sqlobject.SqlUpdate;
import org.skife.jdbi.v2.sqlobject.customizers.RegisterMapperFactory;
import org.skife.jdbi.v2.sqlobject.mixins.Transactional;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.util.jdbi.TCBeanMapperFactory;
import com.appirio.tech.core.service.identity.representation.UserProfile;

/**
 * SSOUserDAO is used to mange the sso user information in the database.
 * 
 * <p>
 * Changes in the version 1.1 in 72h TC Identity Service API Enhancements v1.0
 * - add updateSSOUser method
 * - modify getSSOProviderIdByName to public
 * - add checkUserIdAndProviderId method 
 * </p>
 * 
 * @author TCCoder
 * @version 1.1
 *
 */
public abstract class SSOUserDAO implements Transactional<SocialUserDAO> {

    private static final Logger logger = Logger.getLogger(SSOUserDAO.class);


    @SqlQuery(
            "SELECT user_id FROM user_sso_login " +
            "WHERE sso_user_id = :ssoUserId AND provider_id = :providerId"
    )
    abstract Long getUserIdBySSOUserId(@Bind("ssoUserId") String ssoUserId, @Bind("providerId") Long providerId);

    @SqlQuery(
            "SELECT user_id FROM user_sso_login " +
            "WHERE email = :ssoEmail AND provider_id = :providerId"
    )
    abstract Long getUserIdBySSOEmail(@Bind("ssoEmail") String ssoEmail, @Bind("providerId") Long providerId);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery(
            "SELECT " +
                "u.user_id, " +
                "u.sso_user_id AS userId, " +
                "u.sso_user_name AS name, " +
                "u.email AS email, " +
                "p.sso_login_provider_id, " +
                "p.name AS provider, " +
                "p.type AS providerType " +
            "FROM user_sso_login AS u " +
            "LEFT OUTER JOIN sso_login_provider AS p ON u.provider_id = p.sso_login_provider_id " +
            "WHERE u.user_id = :userId"
    )
    public abstract List<UserProfile> findProfilesByUserId(@Bind("userId") Long userId);

    @SqlQuery(
            "SELECT sso_login_provider_id FROM sso_login_provider " +
            "WHERE name = :ssoProvider"
    )
    public abstract Long getSSOProviderIdByName(@Bind("ssoProvider") String ssoProvider);
    
    @SqlUpdate(
            "INSERT INTO user_sso_login(" +
                    "user_id," + 
                    "provider_id," +
                    "sso_user_id," +
                    "sso_user_name," +
                    "email" +
            ") VALUES (" +
                    ":userId," +
                    ":providerId," +
                    ":p.userId," +
                    ":p.name," +
                    ":p.email" +
            ")")
    abstract int createSSOUser(@Bind("userId") Long userId, @Bind("providerId") Long providerId, @BindBean("p") UserProfile profile);
   
    /**
     * Update sso user
     *
     * @param userId the userId to use
     * @param providerId the providerId to use
     * @param profile the profile to use
     * @return the update affected row number
     */
    @SqlUpdate(
            "UPDATE user_sso_login " +
                    "SET user_id = :userId," + 
                    "provider_id = :providerId," +
                    "sso_user_id = :p.userId," +
                    "sso_user_name = :p.name," +
                    "email = :p.email" +
            " WHERE " +
                    "user_id = :userId AND " +
                    "provider_id = :providerId")
    abstract int updateSSOUser(@Bind("userId") Long userId, @Bind("providerId") Long providerId, @BindBean("p") UserProfile profile);
    
    /**
     * Delete sso user
     *
     * @param userId the userId to use
     * @param providerId the providerId to use
     * @return the update affected row number
     */
    @SqlUpdate(
            "DELETE from user_sso_login " +
            " WHERE " +
                    "user_id = :userId AND " +
                    "provider_id = :providerId")
    public abstract int deleteSSOUser(@Bind("userId") Long userId, @Bind("providerId") Long providerId);
    
    /**
     * Check user id and provider id
     *
     * @param userId the userId to use
     * @param providerId the providerId to use
     * @return the int result
     */
    @SqlQuery("SELECT count(user_id) from  user_sso_login WHERE user_id = :userId AND provider_id = :providerId")
    public abstract int checkUserIdAndProviderId(@Bind("userId") Long userId, @Bind("providerId") Long providerId);
    
    /**
     * Update sso user
     *
     * @param userId the userId to use
     * @param profile the profile to use
     */
    public void updateSSOUser(Long userId, UserProfile profile) {
        if (userId == null) {
            throw new IllegalArgumentException("userId must be specified.");
        }
        if (profile == null) {
            throw new IllegalArgumentException("profile must be specified.");
        }
        if (profile.getProvider() == null) {
            throw new IllegalArgumentException("profile must have provider.");
        }
        if (profile.getUserId() == null && profile.getEmail() == null) {
            throw new IllegalArgumentException("profile must have at least one of user-id and email");
        }

        Long providerId = getSSOProviderIdByName(profile.getProvider());
        if (providerId == null) {
            throw new IllegalArgumentException("Unsupported provider: " + profile.getProvider());
        }

        updateSSOUser(userId, providerId, profile);
    }
    
    /**
     * Query User ID 
     * @param profile
     * @return the user id
     */
    public Long findUserIdByProfile(UserProfile profile) {
        Long ssoProviderId = getSSOProviderIdByName(profile.getProvider());
        if(ssoProviderId==null) {
            throw new IllegalArgumentException("Unsupported SSO provider: " + profile.getProvider());
        }
        Long userId = getUserIdBySSOEmail(profile.getEmail(), ssoProviderId);
        if(userId==null)
            userId = getUserIdBySSOUserId(profile.getLocalUserId(), ssoProviderId);
        return userId;
    }
    
    public void createSSOUser(Long userId, UserProfile profile) {
        if(userId==null)
            throw new IllegalArgumentException("userId must be specified.");
        if(profile==null)
            throw new IllegalArgumentException("profile must be specified.");
        if(profile.getProvider()==null)
            throw new IllegalArgumentException("profile must have provider.");
        if(profile.getUserId()==null && profile.getEmail()==null)
            throw new IllegalArgumentException("profile must have at least one of user-id and email");
        
        Long providerId = getSSOProviderIdByName(profile.getProvider());
        if(providerId==null)
            throw new IllegalArgumentException("Unsupported provider: " + profile.getProvider());
        
        createSSOUser(userId, providerId, profile);
    }
}