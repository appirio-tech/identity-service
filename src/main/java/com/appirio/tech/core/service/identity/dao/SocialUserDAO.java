package com.appirio.tech.core.service.identity.dao;

import java.util.List;

import org.apache.log4j.Logger;
import org.skife.jdbi.v2.sqlobject.Bind;
import org.skife.jdbi.v2.sqlobject.BindBean;
import org.skife.jdbi.v2.sqlobject.SqlQuery;
import org.skife.jdbi.v2.sqlobject.SqlUpdate;
import org.skife.jdbi.v2.sqlobject.customizers.RegisterMapperFactory;
import org.skife.jdbi.v2.sqlobject.mixins.Transactional;

import com.appirio.tech.core.api.v3.util.jdbi.TCBeanMapperFactory;
import com.appirio.tech.core.service.identity.representation.UserProfile;
import com.appirio.tech.core.service.identity.representation.ProviderType;


public abstract class SocialUserDAO implements Transactional<SocialUserDAO> {
	
	private static final Logger logger = Logger.getLogger(SocialUserDAO.class);

	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlQuery(
			"SELECT " +
					"user_id," + 
					"social_login_provider_id AS providerTypeId, " +
					"social_user_name AS name, " +
					"social_email AS email, " +
					"social_email_verified AS isEmailVerified, " + 
					"social_user_id AS userId " +
			"FROM user_social_login " +
			"WHERE user_id = :userId"
	)
	abstract List<UserProfile> findProfilesByUserId(@Bind("userId") Long userId);
	
	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlQuery(
			"SELECT " +
					"user_id," + 
					"social_login_provider_id AS providerTypeId, " +
					"social_user_name AS name, " +
					"social_email AS email, " +
					"social_email_verified AS isEmailVerified, " + 
					"social_user_id AS userId " +
			"FROM user_social_login " +
			"WHERE user_id = :userId " +
			"AND social_login_provider_id = :providerTypeId"
	)
	abstract List<UserProfile> findProfilesByUserIdAndProvider(@Bind("userId") Long userId,  @Bind("providerTypeId") int providerTypeId);
	
	@SqlQuery(
			"SELECT user_id FROM user_social_login " +
			"WHERE social_user_id = :socialId AND social_login_provider_id = :providerTypeId"
	)
	abstract Long getUserIdBySocialId(@Bind("socialId") String socialId, @Bind("providerTypeId") int providerTypeId);

	@SqlQuery(
			"SELECT user_id FROM user_social_login " +
			"WHERE social_email = :socialEmail AND social_login_provider_id = :providerTypeId AND social_email_verified = :emailVarified"
	)
	abstract Long getUserIdBySocialEmail(@Bind("socialEmail") String socialEmail, @Bind("emailVarified") boolean emailVarified, @Bind("providerTypeId") int providerTypeId);

	
	@SqlQuery(
			"SELECT user_id FROM user_social_login " + 
			"WHERE social_user_name = :socialName AND social_login_provider_id = :providerTypeId"
	)
	abstract Long getUserIdBySocialName(@Bind("socialName") String socialName, @Bind("providerTypeId") int providerTypeId);

	@SqlUpdate(
			"INSERT INTO user_social_login(" +
					"user_id," + 
					"social_login_provider_id," +
					"social_user_name," +
					"social_email," +
					"social_email_verified," + 
					"social_user_id" +
			") VALUES (" +
					":userId," +
					":p.providerTypeId," +
					":p.name," +
					":p.email," +
					":p.emailVerified," + 
					":p.userId" +
			")")
	public abstract int createSocialUser(@Bind("userId") Long userId, @BindBean("p") UserProfile profile);
	
	@SqlUpdate(
			"UPDATE user_social_login set social_user_id = :socialId WHERE user_id = :userId")
	abstract int updateSocialId(@Bind("socialId") String socialId, @Bind("userId") Long userId);
	
	@SqlUpdate(
			"DELETE FROM user_social_login WHERE user_id = :userId AND social_login_provider_id = :providerTypeId")
	abstract int deleteSocialUser(@Bind("userId") Long userId, @Bind("providerTypeId") int providerTypeId);

	
	public boolean socialIdExists(String socialId, ProviderType provider) {
		if(socialId==null)
			throw new IllegalArgumentException("socialId must be specified");
		if(provider==null)
			throw new IllegalArgumentException("provider must be specified");
		
		Long userId = getUserIdBySocialId(socialId, provider.id);
		return userId != null;
	}
	
	public Long findUserIdByProfile(UserProfile profile) {
		if(profile==null)
			throw new IllegalArgumentException("profile must be specified");
		if(profile.getUserId()==null)
			throw new IllegalArgumentException("profile must have userId");
		
		ProviderType providerType = profile.getProviderTypeEnum();
		if(providerType==null)
			throw new IllegalArgumentException("Unknown social provider: "+profile.getProviderType());
		
		Long userId = null;
		try {
			userId = getUserIdBySocialId(profile.getLocalUserId(), providerType.id);
			if(userId!=null)
				return userId;
		} catch (Exception e) {
			logger.error(String.format("Error occurred in querying user with social id. socialId:%s, provider:%s, error:%s", profile.getLocalUserId(), providerType.name, e.getMessage()), e);
		}
		
		if(profile.getEmail()!=null && profile.getEmail().length()>0) {
			userId = getUserIdBySocialEmail(profile.getEmail(), profile.isEmailVerified(), providerType.id);
		}
		else if(profile.getName()!=null && profile.getName().length()>0) {
			userId = getUserIdBySocialName(profile.getName(), providerType.id);
		}
		else {
			throw new IllegalArgumentException("The social account should have at least one valid email or one valid username.");
		}
		if(userId!=null) {
			try {
				updateSocialId(profile.getLocalUserId(), userId);
			} catch (Exception e) {
				logger.error(String.format("Failed to update user with social id. userId:%s, socialId:%s error: %s", userId, profile.getLocalUserId(), e.getMessage()), e);
			}
		}
		return userId;
	}
}
