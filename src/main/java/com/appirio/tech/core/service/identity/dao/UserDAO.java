package com.appirio.tech.core.service.identity.dao;

import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.log4j.Logger;
import org.skife.jdbi.v2.TransactionIsolationLevel;
import org.skife.jdbi.v2.sqlobject.Bind;
import org.skife.jdbi.v2.sqlobject.BindBean;
import org.skife.jdbi.v2.sqlobject.CreateSqlObject;
import org.skife.jdbi.v2.sqlobject.SqlQuery;
import org.skife.jdbi.v2.sqlobject.SqlUpdate;
import org.skife.jdbi.v2.sqlobject.Transaction;
import org.skife.jdbi.v2.sqlobject.customizers.Define;
import org.skife.jdbi.v2.sqlobject.customizers.RegisterMapperFactory;
import org.skife.jdbi.v2.sqlobject.mixins.Transactional;
import org.skife.jdbi.v2.sqlobject.stringtemplate.UseStringTemplate3StatementLocator;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.dao.DaoBase;
import com.appirio.tech.core.api.v3.request.FieldSelector;
import com.appirio.tech.core.api.v3.request.FilterParameter;
import com.appirio.tech.core.api.v3.request.LimitQuery;
import com.appirio.tech.core.api.v3.request.OrderByQuery.OrderByItem;
import com.appirio.tech.core.api.v3.request.QueryParameter;
import com.appirio.tech.core.api.v3.util.jdbi.TCBeanMapperFactory;
import com.appirio.tech.core.service.identity.dao.ExternalAccountDAO.ExternalAccount;
import com.appirio.tech.core.service.identity.representation.Achievement;
import com.appirio.tech.core.service.identity.representation.Country;
import com.appirio.tech.core.service.identity.representation.Credential;
import com.appirio.tech.core.service.identity.representation.User2fa;
import com.appirio.tech.core.service.identity.representation.UserDiceAttributes;
import com.appirio.tech.core.service.identity.representation.UserOtp;
import com.appirio.tech.core.service.identity.representation.Email;
import com.appirio.tech.core.service.identity.representation.ProviderType;
import com.appirio.tech.core.service.identity.representation.User;
import com.appirio.tech.core.service.identity.representation.UserProfile;
import com.appirio.tech.core.service.identity.util.Constants;
import com.appirio.tech.core.service.identity.util.UserQueryHelper;
import com.appirio.tech.core.service.identity.util.UserQueryHelper.ConditionBuilder;
import com.appirio.tech.core.service.identity.util.Utils;
import com.appirio.tech.core.service.identity.util.Utils.NumberTrimmingTokenExtractor;
import com.appirio.tech.core.service.identity.util.Utils.RegexTokenExtractor;
import com.appirio.tech.core.service.identity.util.Utils.TokenExtractor;
import com.appirio.tech.core.service.identity.util.idgen.SequenceDAO;

/**
 * UserDAO is used to manage the user
 * 
 * <p>
 * Changes in the version 1.1 72h TC Identity Service API Enhancements v1.0
 * - populateById method is changed to add the sso login flag for the user as
 * well as the provider information stored in the profiles field.
 * </p>
 * 
 * @author TCCoder
 * @version 1.0
 *
 */
@UseStringTemplate3StatementLocator
public abstract class UserDAO implements DaoBase<User>, Transactional<UserDAO> {

    private static final Logger logger = Logger.getLogger(UserDAO.class);

    /** default groups */
    public static final long[] DEFAULT_GROUPS = new long[] {
            2, // Manager
            10, // Coders
            14, // Level Two Admins
            2000118, // Annonymous
    };

    /** patterns used to detect invalid handles */
    public static final Pattern[] INVALID_HANDLE_PATTERNS = new Pattern[] {
            Pattern.compile("(.*?)es"),
            Pattern.compile("(.*?)s"),
            Pattern.compile("_*(.*?)_*"),
    };

    /** the default value for limit in find query */
    public static final int DEFAULT_LIMIT = 500;

    public static final String USER_COLUMNS = "u.user_id AS id, u.first_name AS firstName, u.last_name AS lastName, u.handle, "
            +
            "u.create_date AS createdAt, u.modify_date AS modifiedAt, reg_source AS regSource, " +
            "u.utm_source AS utmSource, u.utm_medium AS utmMedium, u.utm_campaign AS utmCampaign, " +
            "u.status AS status, u.activation_code AS credential$activationCode";

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT " + USER_COLUMNS + ", " +
            "s.password AS credential$encodedPassword, e.address AS email, e.status_id AS emailStatus " +
            "FROM common_oltp.user AS u " +
            "LEFT OUTER JOIN common_oltp.email AS e ON u.user_id = e.user_id AND e.email_type_id = 1 AND e.primary_ind = 1 "
            +
            "LEFT OUTER JOIN common_oltp.security_user AS s ON u.user_id = s.login_id " +
            "WHERE u.user_id = :id")
    public abstract User findUserById(@Bind("id") long id);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT " + USER_COLUMNS + ", " +
            "s.password AS credential$encodedPassword, e.address AS email, e.status_id AS emailStatus " +
            "FROM common_oltp.user AS u " +
            "LEFT OUTER JOIN common_oltp.email AS e ON u.user_id = e.user_id AND e.email_type_id = 1 " +
            "LEFT OUTER JOIN common_oltp.security_user AS s ON u.user_id = s.login_id " +
            "WHERE u.handle_lower = LOWER(:handle)")
    public abstract User findUserByHandle(@Bind("handle") String handle);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT " + USER_COLUMNS + ", " +
            "e.address AS email, e.status_id AS emailStatus, " +
            "mfa.mfa_enabled AS mfaEnabled, mfa.dice_enabled AS diceEnabled " +
            "FROM common_oltp.user AS u " +
            "LEFT OUTER JOIN common_oltp.email AS e ON u.user_id = e.user_id AND e.email_type_id = 1 " +
            "LEFT JOIN common_oltp.user_2fa mfa ON mfa.user_id = u.user_id " +
            "WHERE u.handle_lower = LOWER(:handle)")
    public abstract User findUserWith2faByHandle(@Bind("handle") String handle);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT " + USER_COLUMNS + ", " +
            "s.password AS credential$encodedPassword, e.address AS email, e.status_id AS emailStatus " +
            "FROM common_oltp.user AS u " +
            "LEFT OUTER JOIN common_oltp.email AS e ON u.user_id = e.user_id AND e.email_type_id = 1 AND e.primary_ind = 1 " +
            "LEFT OUTER JOIN common_oltp.security_user AS s ON u.user_id = s.login_id " +
            "WHERE LOWER(e.address) = LOWER(:email)")
    public abstract List<User> findUsersByEmail(@Bind("email") String email);

    @SqlQuery("SELECT COUNT(e2.email_id) " +
            "FROM common_oltp.user AS u LEFT JOIN common_oltp.email AS e ON e.user_id = u.user_id AND e.email_type_id = 1 "
            +
            "LEFT JOIN common_oltp.email AS e2 ON LOWER(e2.address) = LOWER(e.address) " +
            "WHERE u.user_id = :userId")
    public abstract int getEmailCount(@Bind("userId") long userId);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT mfa.id AS mfaId, u.user_id AS userId, u.handle AS handle, u.first_name AS firstName, mfa.mfa_enabled AS mfaEnabled, mfa.dice_enabled AS diceEnabled"
            +
            ", dc.id AS diceConnectionId, dc.connection AS diceConnection, dc.short_url AS connectionUrl, dc.accepted AS diceConnectionAccepted, dc.created_at AS diceJobCreatedAt"
            +
            ", dc.con_created_at AS diceConnectionCreatedAt " +
            "FROM common_oltp.user AS u " +
            "LEFT JOIN common_oltp.user_2fa AS mfa ON mfa.user_id = u.user_id " +
            "LEFT JOIN common_oltp.dice_connection AS dc ON dc.user_id = u.user_id " +
            "WHERE u.user_id = :userId")
    public abstract UserDiceAttributes findUserDiceByUserId(@Bind("userId") long userId);

    @SqlUpdate("INSERT INTO common_oltp.dice_connection " +
            "(user_id) VALUES " +
            "(:userId)")
    public abstract long insertDiceConnection(@Bind("userId") long userId);

    @SqlUpdate("DELETE FROM common_oltp.dice_connection " +
            "WHERE user_id=:userId")
    public abstract int deleteDiceConnection(@Bind("userId") long userId);

    @SqlUpdate("UPDATE common_oltp.dice_connection SET " +
            "connection=null, short_url=null, accepted=false, created_at=current_timestamp, con_created_at=null " +
            "WHERE id=:id")
    public abstract int renewDiceConnection(@Bind("id") long id);

    @SqlUpdate("UPDATE common_oltp.dice_connection SET " +
            "connection=:connection, short_url=:shortUrl, con_created_at = current_timestamp " +
            "WHERE user_id=(SELECT e.user_id FROM common_oltp.email AS e LEFT JOIN common_oltp.user_2fa AS fa ON fa.user_id = e.user_id "
            +
            "WHERE e.address=:email AND e.email_type_id = 1 AND fa.dice_enabled = false)")
    public abstract int updateDiceConnection(@Bind("email") String email, @Bind("connection") String connection,
            @Bind("shortUrl") String shortUrl);

    @SqlUpdate("UPDATE common_oltp.dice_connection SET " +
            "accepted=:accepted " +
            "WHERE connection=:connection")
    public abstract int updateDiceConnectionStatus(@Bind("connection") String connection,
            @Bind("accepted") boolean accepted);

    @SqlUpdate("UPDATE common_oltp.user_2fa SET " +
            "dice_enabled=true, modified_at=current_timestamp " +
            "WHERE user_id=(SELECT user_id FROM common_oltp.dice_connection WHERE connection=:connection) " +
            "AND mfa_enabled = true")
    public abstract int enableDiceByConnectionId(@Bind("connection") String connection);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT mfa.id AS id, mfa.user_id AS userId, mfa.mfa_enabled AS mfaEnabled, mfa.dice_enabled AS diceEnabled, mfa.created_by AS createdBy, mfa.created_at AS createdAt, mfa.modified_by AS modifiedBy, mfa.modified_at AS modifiedAt "
            +
            "FROM common_oltp.user_2fa AS mfa " +
            "WHERE mfa.id = :id")
    public abstract User2fa findUser2faById(@Bind("id") long id);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT mfa.id AS id, u.user_id AS userId, u.handle AS handle, mfa.mfa_enabled AS mfaEnabled, mfa.dice_enabled AS diceEnabled, mfa.created_by AS createdBy, mfa.created_at AS createdAt, mfa.modified_by AS modifiedBy, mfa.modified_at AS modifiedAt "
            +
            "FROM common_oltp.user AS u " +
            "LEFT JOIN common_oltp.user_2fa AS mfa ON mfa.user_id = u.user_id " +
            "WHERE u.user_id = :userId")
    public abstract User2fa findUser2faByUserId(@Bind("userId") long userId);

    @SqlQuery("INSERT INTO common_oltp.user_2fa " +
            "(user_id, mfa_enabled, dice_enabled, created_by, modified_by) VALUES " +
            "(:userId, :mfaEnabled, :diceEnabled, :createdBy, :createdBy) RETURNING id")
    public abstract long insertUser2fa(@Bind("userId") long userId, @Bind("mfaEnabled") boolean mfaEnabled,
            @Bind("diceEnabled") boolean diceEnabled, @Bind("createdBy") Long createdBy);

    @SqlUpdate("UPDATE common_oltp.user_2fa SET " +
            "mfa_enabled=:mfaEnabled, dice_enabled=:diceEnabled, " +
            "modified_by=:modifiedBy, modified_at=current_timestamp " +
            "WHERE id=:id")
    public abstract int updateUser2fa(@Bind("id") long id, @Bind("mfaEnabled") boolean mfaEnabled,
            @Bind("diceEnabled") boolean diceEnabled, @Bind("modifiedBy") Long modifiedBy);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT otp.id AS id, u.user_id AS userId, u.handle AS handle, u.status AS status, otp.otp AS otp, otp.expire_at AS expireAt, otp.resend AS resend, otp.fail_count AS failCount "
            +
            "FROM common_oltp.user AS u " +
            "LEFT JOIN common_oltp.user_otp_email AS otp ON otp.user_id = u.user_id AND otp.mode = :mode " +
            "WHERE u.user_id = :userId")
    public abstract UserOtp findUserOtpByUserId(@Bind("userId") long userId, @Bind("mode") int mode);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT otp.id AS id, u.user_id AS userId, u.handle AS handle, e.address AS email, otp.otp AS otp, otp.expire_at AS expireAt, otp.resend AS resend, otp.fail_count AS failCount "
            +
            "FROM common_oltp.user AS u " +
            "JOIN common_oltp.email AS e ON e.user_id = u.user_id AND e.email_type_id = 1 AND e.primary_ind = 1 " +
            "LEFT JOIN common_oltp.user_otp_email AS otp ON otp.user_id = u.user_id AND otp.mode = :mode " +
            "WHERE u.user_id = :userId")
    public abstract UserOtp findUserOtpEmailByUserId(@Bind("userId") long userId, @Bind("mode") int mode);

    @SqlUpdate("UPDATE common_oltp.user_otp_email SET " +
            "otp=:otp, " +
            "expire_at=current_timestamp + (:duration ||' minutes')::interval, " +
            "resend=:resend, " +
            "fail_count=:failCount " +
            "WHERE id=:id")
    public abstract int updateUserOtp(@Bind("id") long id, @Bind("otp") String otp, @Bind("duration") int duration,
            @Bind("resend") boolean resend, @Bind("failCount") int failCount);

    @SqlUpdate("UPDATE common_oltp.user_otp_email SET " +
            "expire_at=current_timestamp + (:duration ||' minutes')::interval, " +
            "resend=:resend " +
            "WHERE id=:id")
    public abstract int updateUserOtpResend(@Bind("id") long id, @Bind("duration") int duration,
            @Bind("resend") boolean resend);

    @SqlUpdate("UPDATE common_oltp.user_otp_email SET " +
            "fail_count=:failCount " +
            "WHERE id=:id")
    public abstract int updateUserOtpAttempt(@Bind("id") long id, @Bind("failCount") int failCount);

    @SqlUpdate("INSERT INTO common_oltp.user_otp_email " +
            "(user_id, mode, otp, expire_at, resend, fail_count) VALUES " +
            "(:userId, :mode, :otp, current_timestamp + (:duration ||' minutes')::interval, :resend, :failCount)")
    public abstract int insertUserOtp(@Bind("userId") long userId, @Bind("mode") int mode, @Bind("otp") String otp,
            @Bind("duration") int duration, @Bind("resend") boolean resend, @Bind("failCount") int failCount);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT " + USER_COLUMNS + ", " +
            "e.address AS email, e.status_id AS emailStatus " +
            "FROM common_oltp.user AS u JOIN common_oltp.email AS e ON e.user_id = u.user_id " +
            "WHERE e.address = :email")
    public abstract List<User> findUsersByEmailCS(@Bind("email") String email);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT " + USER_COLUMNS + ", " +
            "e.address AS email, e.status_id AS emailStatus, " +
            "mfa.mfa_enabled AS mfaEnabled, mfa.dice_enabled AS diceEnabled " +
            "FROM common_oltp.user AS u JOIN common_oltp.email AS e ON e.user_id = u.user_id " +
            "LEFT JOIN common_oltp.user_2fa AS mfa ON mfa.user_id = u.user_id " +
            "WHERE e.address = :email")
    public abstract List<User> findUsersWith2faByEmailCS(@Bind("email") String email);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT " + USER_COLUMNS + ", " +
            "e.address AS email, e.status_id AS emailStatus " +
            "FROM common_oltp.user AS u " +
            "LEFT JOIN common_oltp.user_2fa AS mfa ON mfa.user_id = u.user_id " +
            "<joinOnEmail> common_oltp.email AS e ON u.user_id = e.user_id AND e.primary_ind = 1 " +
            "<condition> " +
            "<order> " +
            "<offset> <limit>")
    protected abstract List<User> findUsers(@BindBean("u") User user, @Define("joinOnEmail") String joinOnEmail,
            @Define("condition") String condition, @Define("order") String order, @Define("offset") String offset,
            @Define("limit") String limit);

    public static final String COUNTRY_COLUMNS = "country_code AS code, country_name AS name, " +
            "iso_alpha2_code AS isoAlpha2Code, iso_alpha3_code AS isoAlpha3Code";

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT " + COUNTRY_COLUMNS + " FROM common_oltp.country " +
            "WHERE LOWER(country_name) = lower(:name) OR LOWER(iso_name) = lower(:name)")
    public abstract Country findCountryByName(@Bind("name") String countryName);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT " + COUNTRY_COLUMNS + " FROM common_oltp.country " +
            "WHERE country_code = :code")
    public abstract Country findCountryByCode(@Bind("code") String countryCode);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT " + COUNTRY_COLUMNS + " FROM common_oltp.country " +
            "WHERE iso_alpha3_code = :code")
    public abstract Country findCountryByISOAlpha3Code(@Bind("code") String isoAlpha3Code);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT " + COUNTRY_COLUMNS + " FROM common_oltp.country " +
            "WHERE iso_alpha2_code = :code")
    public abstract Country findCountryByISOAlpha2Code(@Bind("code") String isoAlpha2Code);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT " + COUNTRY_COLUMNS + " " +
            "FROM common_oltp.country AS c" +
            "JOIN informixoltp.coder AS u ON u.comp_country_code = c.country_code " +
            "WHERE u.coder_id = :coderId")
    public abstract Country findCountryByCoderId(@Bind("coderId") long coderId);

    @SqlQuery("SELECT count(*) AS count " +
            "FROM common_oltp.invalid_handles " +
            "WHERE invalid_handle = LOWER(:handle)")
    abstract int checkInvalidHandle(@Bind("handle") String handle);

    @RegisterMapperFactory(TCBeanMapperFactory.class)
    @SqlQuery("SELECT " +
            "a.description AS description, a.achievement_type_id AS typeId, t.achievement_type_desc AS type, " +
            "a.achievement_date AS achievementDate, a.create_date AS createdAt " +
            "FROM common_oltp.user_achievement AS a " +
            "LEFT OUTER JOIN common_oltp.achievement_type_lu AS t ON a.achievement_type_id = t.achievement_type_id " +
            "WHERE a.user_id = :userId " +
            "ORDER BY a.create_date DESC")
    public abstract List<Achievement> findAchievements(@Bind("userId") long userId);

    @SqlUpdate("INSERT INTO common_oltp.user " +
            "(user_id, first_name, last_name, handle, status, reg_source, utm_source, utm_medium, utm_campaign) VALUES "
            +
            "(:u.id, :u.firstName, :u.lastName, :u.handle, :u.status, :u.regSource, :u.utmSource, :u.utmMedium, :u.utmCampaign)")
    abstract int createUser(@BindBean("u") User user);

    @SqlUpdate("UPDATE common_oltp.user SET " +
            "first_name=:u.firstName, last_name=:u.lastName, " +
            "reg_source=:u.regSource, utm_source=:u.utmSource, " +
            "utm_medium=:u.utmMedium, utm_campaign=:u.utmCampaign " +
            "WHERE user_id=:u.id")
    abstract int updateUser(@BindBean("u") User user);

    @SqlUpdate("INSERT INTO common_oltp.security_user" +
            "(login_id, user_id, password) VALUES " +
            "(:loginId, :userId, :encodedPassword)")
    abstract int createSecurityUser(@Bind("loginId") long userId, @Bind("userId") String handle,
            @Bind("encodedPassword") String encodedPassword);

    @SqlUpdate("INSERT INTO informixoltp.coder" +
            "(coder_id, quote, coder_type_id, home_country_code, comp_country_code, display_quote, quote_location, quote_color, display_banner, banner_style) VALUES "
            +
            "(:coderId, '', 2, :countryCode, :countryCode,  1, 'md', '#000000', 1, 'bannerStyle4')")
    abstract int createCoder(@Bind("coderId") long coderId, @Bind("countryCode") String countryCode);

    @SqlUpdate("INSERT INTO informixoltp.algo_rating " +
            "(coder_id, rating, vol, round_id, num_ratings, algo_rating_type_id, modify_date) VALUES " +
            "(:userId, 0, 0, 0, 0, 1, current_timestamp)")
    abstract int cretateAlgoRating(@Bind("userId") long userId);

    @SqlUpdate("INSERT INTO common_oltp.user_group_xref " +
            "(user_group_id, login_id, group_id, create_user_id, security_status_id) VALUES " +
            "(:userGroupId, :userId, :groupId, 1, 1)")
    abstract int cretateUserGroupReference(@Bind("userGroupId") long userGroupId, @Bind("userId") long userId,
            @Bind("groupId") long groupId);

    @SqlUpdate("UPDATE common_oltp.user SET handle = :handle WHERE user_id = :userId")
    abstract int updateHandle(@Bind("userId") long userId, @Bind("handle") String handle);

    @SqlUpdate("UPDATE common_oltp.user SET status = :status WHERE user_id = :userId and status != '6'")
    abstract int updateStatus(@Bind("userId") long userId, @Bind("status") String status);

    protected int activateUser(long userId) {
        return updateStatus(userId, "A");
    }

    @SqlUpdate("INSERT INTO common_oltp.user_achievement " +
            "(user_id, achievement_date, achievement_type_id, description, create_date) VALUES " +
            "(:userId, current_date, 2, :comment, current_timestamp)")
    abstract int createUserAchievement(@Bind("userId") long userId, @Bind("comment") String comment);

    @SqlUpdate("UPDATE common_oltp.user set last_login = current_timestamp WHERE user_id = :userId")
    abstract int updateLastLogin(@Bind("userId") long userId);

    @SqlUpdate("UPDATE common_oltp.security_user SET password = :encodedPassword WHERE user_id = :handle")
    abstract int updatePassword(@Bind("handle") String handle, @Bind("encodedPassword") String encodedPassword);

    @SqlUpdate("UPDATE common_oltp.security_user SET user_id = :userId WHERE login_id = :loginId")
    abstract int updateSecurityUserHandle(@Bind("loginId") long userId, @Bind("userId") String handle);

    @SqlUpdate("INSERT INTO informixoltp.coder_referral " +
            "(coder_id, referral_id, reference_id, other) VALUES " +
            "(:userId, 40, (SELECT user_id FROM common_oltp.user WHERE handle_lower = LOWER(:handle)), :handle)")
    abstract int createReferral(@Bind("userId") long userId, @Bind("handle") String handle);

    @CreateSqlObject
    public abstract SequenceDAO createSequenceDAO();

    @CreateSqlObject
    public abstract SocialUserDAO createSocialUserDAO();

    @CreateSqlObject
    public abstract SSOUserDAO createSSOUserDAO();

    @CreateSqlObject
    public abstract EmailDAO createEmailDAO();

    private ExternalAccountDAO externalAccountDao;

    public ExternalAccountDAO getExternalAccountDao() {
        return externalAccountDao;
    }

    public void setExternalAccountDao(ExternalAccountDAO externalAccountDao) {
        this.externalAccountDao = externalAccountDao;
    }

    protected String getSSOTokenSalt() {
        Object ssoTokenSalt = Utils.getContext("ssoTokenSalt");
        return ssoTokenSalt == null ? null : ssoTokenSalt.toString();
    }

    public List<User> findUsers(FilterParameter filterParam, List<OrderByItem> orders, LimitQuery limit) {
        User paramUser = createEmptyUserForSearchCondition();
        String whereClause = buildWhereClause(filterParam, paramUser);
        if (orders != null) {
            // not supported yet
        }
        String offsetClause = buildOffsetClause(limit);
        String limitClause = buildLimitClause(limit);
        String joinOnEmail = buildJoinOnEmail(filterParam);

        return findUsers(paramUser, joinOnEmail, whereClause, null, offsetClause, limitClause);
    }

    protected User createEmptyUserForSearchCondition() {
        User paramUser = new User();
        return paramUser;
    }

    public Email findUserPrimaryEmail(long userId) {
        return createEmailDAO().findPrimaryEmail(userId);
    }

    public User findUserByEmail(String email) {
        if (email == null || email.length() == 0)
            throw new IllegalArgumentException("email must be specified.");

        List<User> users = findUsersByEmail(email);
        if (users == null || users.size() == 0)
            return null;

        if (users.size() == 1)
            return users.get(0);

        // If users are registered as:
        // userA with Appirio@topcoder.com
        // userB with appirio@topcoder.com
        // userC with Appirio@Topcoder.Com
        // findUsersByEmail("appirio@topcoder.com") returns all of them
        // because the parameter "email" is treated in case-insensitive.
        // in case like this, determines result with the exact-match.
        // "userB" is returned for "appirio@topcoder.com" in the example.
        for (User user : users) {
            if (user.getEmail().equals(email))
                return user;
        }

        // nothing matched with email parameter in the result, returns the first one.
        return users.get(0);
    }

    /**
     *
     * @param email - case sensitive search
     * @return an user object or null
     */
    public User findUserByEmailCS(String email) {
        return findUserByEmailCS(email, false);
    }

    /**
     *
     * @param email - case sensitive search
     * @return an user object or null
     */
    public User findUserByEmailCS(String email, Boolean include2fa) {
        if (email == null || email.length() == 0)
            throw new IllegalArgumentException("email must be specified.");

        List<User> users;
        if (include2fa) {
            users = findUsersWith2faByEmailCS(email);
        } else {
            users = findUsersByEmailCS(email);
        }
        if (users == null || users.size() == 0)
            return null;

        // if found multiple, retuning first one
        return users.get(0);
    }

    @Transaction(TransactionIsolationLevel.READ_COMMITTED)
    public TCID register(User user) {
        if (user == null)
            throw new IllegalArgumentException("user must be specified.");

        // generate a new id for user
        Long userId = nextSequeceValue("sequence_user_seq");
        user.setId(new TCID(userId));

        if (user.getCredential() == null) {
            user.setCredential(new Credential());
        }

        // insert user
        createUser(user);

        // insert security_user
        createSecurityUser(
                userId, user.getHandle(),
                user.getCredential().getEncodedPassword());

        // insert coder
        createCoder(user);

        // insert coder_referral
        if (user.isReferralProgramCampaign() && user.getUtmSource() != null) {
            createReferral(user);
        }

        // insert algo_rating
        cretateAlgoRating(userId);

        // insert email
        Long emailId = nextSequeceValue("sequence_email_seq");
        int emailStatusId = user.isActive() ? Constants.EMAIL_STATUS_ID_ACTIVE : Constants.EMAIL_STATUS_ID_INACTIVE;
        registerEmail(userId, emailId, user.getEmail(), emailStatusId);

        // create user_social_login / user_sso_login
        if (user.getProfile() != null) {
            ProviderType providerType = user.getProfile().getProviderTypeEnum();
            if (providerType != null && providerType.isSocial) {
                createSocialUser(userId, user.getProfile());
            }
            if (providerType != null && providerType.isEnterprise && providerType != ProviderType.LDAP) {
                // Handle SSO intermittent login issue #3
                if (user.getProfile() != null && user.getProfile().getEmail() == null)
                    user.getProfile().setEmail(user.getEmail());
                createSSOUserDAO().createSSOUser(userId, user.getProfile());
            }
        }

        // add user to initial groups
        addUserToDefaultGroups(user);

        return user.getId();
    }

    protected int registerEmail(long userId, long emailId, String email, int statusId) {
        return createEmailDAO().createEmail(userId, emailId, email, statusId);
    }

    @Transaction(TransactionIsolationLevel.READ_COMMITTED)
    public void addSocialProfile(Long userId, UserProfile profile) {
        createSocialUser(userId, profile);
    }

    protected void createSocialUser(Long userId, UserProfile profile) {
        if (userId == null)
            throw new IllegalArgumentException("userId must be sopecified.");
        if (profile == null)
            throw new IllegalArgumentException("profile must be specified.");
        if (!profile.isSocial())
            throw new IllegalArgumentException("profile must be social.");

        // create a record in Informix
        createSocialUserDAO().createSocialUser(userId, profile);

        // create an item in External Accounts table(DynamoDB)
        saveExternalAccount(
                createExternalAccount(userId, profile.getProviderTypeEnum(), profile.getContext()));
    }

    protected void saveExternalAccount(ExternalAccount externalAccount) {
        if (externalAccount == null)
            return;
        if (this.externalAccountDao == null)
            throw new IllegalStateException("externalAccountDao must be specified.");
        this.externalAccountDao.put(externalAccount);
    }

    protected ExternalAccount createExternalAccount(Long userId, ProviderType providerType,
            Map<String, String> profileContext) {
        if (userId == null)
            throw new IllegalArgumentException("userId must be specified.");
        if (providerType == null)
            throw new IllegalArgumentException("providerType must be specified.");

        ExternalAccount externalAccount = new ExternalAccount();
        externalAccount.setAccountType(providerType.name);
        externalAccount.setUserId(String.valueOf(userId));
        externalAccount.setParams(profileContext);
        externalAccount.setDeleted(false);
        externalAccount.setHasErrored(false);
        externalAccount.setSynchronizedAt(0L); // must set 0 to fire trigger
        return externalAccount;
    }

    @Override
    @Transaction(TransactionIsolationLevel.READ_COMMITTED)
    public TCID update(User user) throws Exception {
        if (user == null)
            throw new IllegalArgumentException("user must be specified.");
        if (user.getId() == null || user.getId().getId() == null)
            throw new IllegalArgumentException("userId must be specified.");

        updateUser(user);

        return user.getId();
    }

    public Country findCountryBy(Country country) {
        if (country == null)
            return null;
        if (country.getCode() == null && country.getISOAlpha2Code() == null && country.getISOAlpha3Code() == null
                && country.getName() == null)
            return null;

        Country cnt = null;
        if (country.getCode() != null && country.getCode().length() > 0) {
            cnt = findCountryByCode(country.getCode());
        }
        if (cnt == null && country.getISOAlpha2Code() != null && country.getISOAlpha2Code().length() > 0) {
            cnt = findCountryByISOAlpha2Code(country.getISOAlpha2Code());
        }
        if (cnt == null && country.getISOAlpha3Code() != null && country.getISOAlpha3Code().length() > 0) {
            cnt = findCountryByISOAlpha3Code(country.getISOAlpha3Code());
        }
        if (cnt == null && country.getName() != null && country.getName().length() > 0) {
            cnt = findCountryByName(country.getName());
        }
        return cnt;
    }

    protected void createReferral(User user) {
        if (user == null)
            throw new IllegalArgumentException("user must be specifeid.");
        if (user.getUtmSource() == null)
            throw new IllegalArgumentException("utmSource must be specifeid.");

        createReferral(Utils.toLongValue(user.getId()), user.getUtmSource());
    }

    protected void createCoder(User user) {
        if (user == null)
            throw new IllegalArgumentException("user must be specifeid.");

        // coder id (= user id)
        Long coderId = Utils.toLongValue(user.getId());

        // country code
        String countryCode = null;
        Country country = user.getCountry();
        if (country != null) {
            countryCode = getCode(country);
            country.setCode(countryCode);
        }

        // insert coder
        createCoder(coderId, countryCode);
    }

    protected String getCode(Country country) {
        if (country == null)
            return null;
        if (country.getCode() != null)
            return country.getCode();

        Country cnt = findCountryBy(country);
        return cnt != null ? cnt.getCode() : null;
    }

    protected void addUserToGroup(SequenceDAO sequenceDao, User user, Long groupId) {
        long userGroupId = sequenceDao.nextVal("sequence_user_group_seq");
        long userId = Utils.toLongValue(user.getId());
        cretateUserGroupReference(userGroupId, userId, groupId);
    }

    protected void addUserToDefaultGroups(User user) {
        SequenceDAO sequenceDao = createSequenceDAO();
        for (int i = 0; i < DEFAULT_GROUPS.length; i++) {
            addUserToGroup(sequenceDao, user, DEFAULT_GROUPS[i]);
        }
    }

    @Transaction(TransactionIsolationLevel.READ_COMMITTED)
    public void activate(long userId) {
        // user table
        activateUser(userId);
        // email table
        activateEmail(userId);
    }

    @Transaction(TransactionIsolationLevel.READ_COMMITTED)
    public void updateHandle(User user) {
        if (user == null)
            throw new IllegalArgumentException("user must be specified.");
        if (user.getHandle() == null)
            throw new IllegalArgumentException("user must have a handle.");
        if (!Utils.isValid(user.getId()))
            throw new IllegalArgumentException("invalid user id: " + user.getId());

        Long userId = Utils.toLongValue(user.getId());

        // update user table
        updateHandle(userId, user.getHandle());
        // update security_user table
        updateSecurityUserHandle(userId, user.getHandle());
    }

    @Transaction(TransactionIsolationLevel.READ_COMMITTED)
    public Email updatePrimaryEmail(User user) {
        if (user == null)
            throw new IllegalArgumentException("user must be specified.");
        if (user.getEmail() == null)
            throw new IllegalArgumentException("user must have an email.");
        if (!Utils.isValid(user.getId()))
            throw new IllegalArgumentException("invalid user id: " + user.getId());

        Long userId = Utils.toLongValue(user.getId());

        EmailDAO emailDao = createEmailDAO();
        Email primayEmail = emailDao.findPrimaryEmail(userId);
        if (primayEmail == null) {
            return null;
        }

        primayEmail.setAddress(user.getEmail());
        emailDao.update(primayEmail);

        return primayEmail;
    }

    @Transaction(TransactionIsolationLevel.READ_COMMITTED)
    public void updateStatus(User user, String comment) {
        if (user == null)
            throw new IllegalArgumentException("user must be specified.");
        if (user.getStatus() == null)
            throw new IllegalArgumentException("user must have a status.");
        if (!Utils.isValid(user.getId()))
            throw new IllegalArgumentException("invalid user id: " + user.getId());

        Long userId = Utils.toLongValue(user.getId());

        // update table
        updateStatus(userId, user.getStatus());
        // user_achievement table
        if (comment != null && comment.trim().length() > 0) {
            createUserAchievement(userId, comment);
        }
        // Fix for COR-523
        // activate the primary email if it's not active when user is active.
        if (user.isActive() && !user.isEmailActive()) {
            activateEmail(userId);
            user.setEmailStatus(User.INTERNAL_EMAIL_STATUS_ACTIVE);
        }
    }

    /**
     * Authenticate a user by specified handle/email and password with the database.
     * 
     * @param handleOrEmail handle or email.
     * @param password
     * @return User object which is identified by handleOrEmail
     */
    public User authenticate(String handleOrEmail, String password) {
        if (handleOrEmail == null)
            throw new IllegalArgumentException("handleOrEmail must be specified.");
        if (password == null)
            throw new IllegalArgumentException("password must be specified.");

        User user = Utils.isEmail(handleOrEmail) ? findUserByEmail(handleOrEmail) : findUserByHandle(handleOrEmail);
        return authenticate(user, password);
    }

    /**
     * Authenticate a user by specified userId and password with the database.
     * 
     * @param userId
     * @param password
     * @return User object which is identified by userId
     */
    public User authenticate(Long userId, String password) {
        if (userId == null)
            throw new IllegalArgumentException("userId must be specified.");
        if (password == null)
            throw new IllegalArgumentException("password must be specified.");

        User user = findUserById(userId);

        return authenticate(user, password);
    }

    protected User authenticate(User user, String password) {
        if (user == null)
        {
            logger.info("No user provided to authenticate");
            return null;
        }
        if (password == null)
            throw new IllegalArgumentException("password must be specified.");
        
        if(user.getCredential().getEncodedPassword().trim().equals(Utils.encodePassword(password))){
            return user; //Authentication successful
        } else {
            return null; //Authentication failed
        }
    }

    @Transaction(TransactionIsolationLevel.READ_COMMITTED)
    public void updatePassword(User user) {
        if (user == null)
            throw new IllegalArgumentException("user must be specified.");
        if (user.getHandle() == null)
            throw new IllegalArgumentException("handle must be specified.");
        if (user.getCredential() == null || user.getCredential().getPassword() == null)
            throw new IllegalArgumentException("password must be specified.");

        // update security_user table
        updatePassword(user.getHandle(), user.getCredential().getEncodedPassword());
    }

    @Transaction(TransactionIsolationLevel.READ_COMMITTED)
    public void updateLastLoginDate(User user) {
        if (user == null)
            throw new IllegalArgumentException("user must be specified.");

        updateLastLogin(Utils.toLongValue(user.getId()));
    }

    protected Long nextSequeceValue(String seqenceName) {
        if (seqenceName == null)
            throw new IllegalArgumentException("seqenceName must be specified.");
        SequenceDAO sequenceDao = createSequenceDAO();

        return sequenceDao.nextVal(seqenceName);
    }

    protected int activateEmail(long userId) {
        return createEmailDAO().activateEmail(userId);
    }

    public boolean handleExists(String handle) {
        if (handle == null)
            return false;
        User user = findUserByHandle(handle);
        return user != null;
    }

    public boolean socialUserExists(UserProfile profile) {
        if (profile == null)
            return false;
        return createSocialUserDAO().socialIdExists(
                profile.getUserId(),
                profile.getProviderTypeEnum());
    }

    public boolean ssoUserExists(UserProfile profile) {
        if (profile == null)
            return false;
        return createSSOUserDAO().findUserIdByProfile(profile) != null;
    }

    public boolean emailExists(String email) {
        return createEmailDAO().emailExists(email);
    }

    public List<UserProfile> getSocialProfiles(Long userId) {
        if (userId == null)
            throw new IllegalArgumentException("userId must be specified.");
        return createSocialUserDAO().findProfilesByUserId(userId);
    }

    public List<UserProfile> getSocialProfiles(Long userId, ProviderType providerType) {
        if (userId == null)
            throw new IllegalArgumentException("userId must be specified.");
        if (providerType == null)
            throw new IllegalArgumentException("providerType must be specified.");
        if (!providerType.isSocial)
            throw new IllegalArgumentException("providerType must be social.");

        return createSocialUserDAO().findProfilesByUserIdAndProvider(userId, providerType.id);
    }

    @Transaction(TransactionIsolationLevel.READ_COMMITTED)
    public void deleteSocialProfiles(Long userId, ProviderType providerType) {
        if (userId == null)
            throw new IllegalArgumentException("userId must be specified.");
        if (providerType == null)
            throw new IllegalArgumentException("providerType must be specified.");
        if (!providerType.isSocial)
            throw new IllegalArgumentException("providerType must be social.");

        logger.debug(String.format("deleteSocialUser(%s, %s)", userId, providerType.name));
        int delCount = createSocialUserDAO().deleteSocialUser(userId, providerType.id);
        logger.debug(String.format("deleteSocialUser(%s, %s) removed %d records", userId, providerType.name, delCount));

        ExternalAccount externalAccount = createExternalAccount(userId, providerType, null);
        externalAccountDao.delete(externalAccount);
    }

    public List<UserProfile> getSSOProfiles(Long userId) {
        if (userId == null)
            throw new IllegalArgumentException("userId must be specified.");
        return createSSOUserDAO().findProfilesByUserId(userId);
    }

    public Long getUserId(UserProfile profile) {
        if (profile == null)
            throw new IllegalArgumentException("profile must be specified.");

        ProviderType providerType = profile.getProviderTypeEnum();
        if (providerType == null)
            throw new IllegalArgumentException("Unsupported provider type: " + profile.getProviderType());

        // LDAP or Auth0 Custom database(TC-User-Database)
        if (providerType == ProviderType.LDAP || providerType == ProviderType.AUTH0) {
            String userId = profile.getLocalUserId();
            if (userId == null)
                throw new IllegalArgumentException("Unexpected profile data. Missing user ID.");
            return Long.valueOf(userId);
        }

        // Social
        if (providerType != null && providerType.isSocial) {
            return createSocialUserDAO().findUserIdByProfile(profile);
        }
        // Enterprise
        if (providerType != null && providerType.isEnterprise) {
            return createSSOUserDAO().findUserIdByProfile(profile);
        }

        throw new IllegalArgumentException("Unsupported provider type: " + profile.getProviderType());
    }

    public boolean isInvalidHandle(String handle) {
        if (handle == null)
            return false;

        Set<String> checkedHandles = new HashSet<String>();
        // checking the handle with exact matching with NG words registered in the
        // database
        if (isExactInvalidHandle(handle))
            return true;
        checkedHandles.add(handle);

        // breaking the handle into tokens and checking them by
        // isExactInvalidHandle(token)
        // trying 2 ways to extract tokens (NumberTrimmingTokenExtractor,
        // isHandleContainingNGWord)
        if (isHandleContainingNGWord(handle, new NumberTrimmingTokenExtractor(checkedHandles)))
            return true;
        return isHandleContainingNGWord(handle, new RegexTokenExtractor(INVALID_HANDLE_PATTERNS, checkedHandles));
    }

    protected boolean isHandleContainingNGWord(String handle, TokenExtractor tokenExtractor) {
        if (handle == null)
            return false;

        // breaking the handle into tokens
        Set<String> extractedHandles = tokenExtractor.extractTokens(handle);
        if (extractedHandles == null || extractedHandles.size() == 0)
            return false;

        // check each token
        for (Iterator<String> iter = extractedHandles.iterator(); iter.hasNext();) {
            if (isExactInvalidHandle(iter.next()))
                return true;
        }
        return false;
    }

    /**
     * checks the given handle is a NG word registered in database.
     * 
     * @param handle
     * @return
     */
    public boolean isExactInvalidHandle(String handle) {
        if (handle == null)
            return false;

        boolean result = checkInvalidHandle(handle) > 0;
        logger.debug(String.format("isExactInvalidHandle('%s'): %s", handle, result));
        return result;
    }

    /**
     * Generates a "tcsso" token for the specifed user.
     * 
     * @param userId
     * @return
     * @throws Exception
     */
    public String generateSSOToken(Long userId) throws Exception {
        if (userId == null)
            throw new IllegalArgumentException("userId must be specified.");

        User user = findUserById(userId);
        if (user == null)
            throw new IllegalArgumentException("userId doesn't exist.");

        String password = user.getCredential().getEncodedPassword();
        String status = user.getStatus();

        return generateSSOToken(userId, password, status);
    }

    /**
     * Generates a tcsso token: {userId}|hash({secret}{userId}{password}{status})
     * 
     * @see com.topcoder.web.common.security.SecurityTokenGeneratorImpl
     */
    protected String generateSSOToken(Long userId, String password, String status) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String salt = getSSOTokenSalt();
        if (salt == null)
            throw new IllegalArgumentException("Failed to generate SSO token. Invalid configuration.");
        byte[] plain = (salt + userId + password + status).getBytes("UTF-8");
        byte[] raw = md.digest(plain);
        StringBuffer hash = new StringBuffer();
        for (byte aRaw : raw)
            hash.append(Integer.toHexString(aRaw & 0xff));
        return userId + "|" + hash.toString();
    }

    @Override
    public List<User> populate(QueryParameter query) throws Exception {
        return null;
    }

    /**
     * Populate user by user id
     *
     * @param selector the selector to use
     * @param id       the id to use
     * @throws Exception if any error occurs
     * @return the User result
     */
    @Override
    public User populateById(FieldSelector selector, TCID id) throws Exception {
        if (id == null || !Utils.isValid(id)) {
            throw new IllegalArgumentException("Specified id is invalid. id: " + id);
        }

        Long userId = Utils.toLongValue(id);
        User user = findUserById(userId);

        SSOUserDAO ssoUserDao = this.createSSOUserDAO();
        List<UserProfile> profiles = ssoUserDao.findProfilesByUserId(userId);
        if (profiles != null && profiles.size() > 0) {
            // return the profiles anyway if the sso login is true
            user.setSsoLogin(true);
            user.setProfiles(profiles);
        }
        // profiles
        if (hasField(selector, "profiles") && !user.isSsoLogin()) {
            user.setProfiles(createSocialUserDAO().findProfilesByUserId(userId));
        }

        return user;
    }

    protected boolean hasField(FieldSelector selector, String field) {
        if (field == null)
            throw new IllegalArgumentException("field must be specified.");

        if (selector == null || selector.getSelectedFields() == null)
            return false;
        for (Iterator<String> iter = selector.getSelectedFields().iterator(); iter.hasNext();) {
            String specifiedField = iter.next();
            if (specifiedField.equals(field) || specifiedField.startsWith(field + "("))
                return true;
        }
        return false;
    }

    @Override
    public TCID insert(User user) throws Exception {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    @Override
    public void delete(TCID id) throws Exception {
        throw new UnsupportedOperationException("Not implemented yet.");
    }

    protected String buildLimitClause(LimitQuery limit) {
        int lim = (limit != null && limit.getLimit() != null) ? limit.getLimit() : DEFAULT_LIMIT;
        if (lim < 1)
            throw new IllegalArgumentException("limit must be a positive integer. specified: " + lim);

        return new StringBuilder()
                .append("LIMIT ")
                .append(lim).toString();
    }

    protected String buildOffsetClause(LimitQuery limit) {
        if (limit == null || limit.getOffset() == null || limit.getOffset() == 0)
            return null;
        if (limit.getOffset() < 0)
            throw new IllegalArgumentException(
                    "offset must be a positive integer or zero. specified: " + limit.getOffset());

        return new StringBuilder()
                .append("OFFSET ")
                .append(limit.getOffset()).toString();
    }

    protected String buildJoinOnEmail(FilterParameter filterParam) {
        // if email is specified in parameters, expected users should have email. ->
        // INNER JOIN
        // otherwise -> OUTER JOIN
        return (filterParam != null && filterParam.getParamMap() != null
                && filterParam.getParamMap().containsKey("email")) ? "INNER JOIN" : "LEFT OUTER JOIN";
    }

    protected UserQueryHelper createQueryHelper() {
        return new UserQueryHelper();
    }

    protected String buildWhereClause(FilterParameter filterParam, User user) {
        if (filterParam == null || filterParam.getParamMap() == null || filterParam.getParamMap().size() == 0)
            return null;

        StringBuilder whereClause = new StringBuilder();
        Map<String, Object> params = filterParam.getParamMap();
        populate(user, params);
        for (String param : params.keySet()) {
            ConditionBuilder cb = createQueryHelper().createConditionBuilder(param, user, whereClause);
            if (cb != null) {
                cb.build(filterParam.isLike());
            }
        }
        if (whereClause.length() > 0)
            whereClause.insert(0, " WHERE ");
        return whereClause.toString();
    }

    protected void populate(User user, Map<String, Object> params) {
        Map<String, Object> paramsClone = new HashMap<String, Object>();
        paramsClone.putAll(params);
        if (paramsClone.containsKey("id")) {
            TCID tcid = new TCID((String) paramsClone.get("id"));
            if (!Utils.isValid(tcid)) {
                throw new IllegalArgumentException("Invalid value for 'id': " + paramsClone.get("id"));
            }
            user.setId(tcid);
            paramsClone.remove("id");
        }
        try {
            BeanUtils.populate(user, paramsClone);
        } catch (Exception e) {
            logger.debug(e.getMessage());
        }
    }
}
