package com.appirio.tech.core.service.identity.dao;

import org.apache.log4j.Logger;
import org.skife.jdbi.v2.sqlobject.Bind;
import org.skife.jdbi.v2.sqlobject.BindBean;
import org.skife.jdbi.v2.sqlobject.SqlQuery;
import org.skife.jdbi.v2.sqlobject.SqlUpdate;
import org.skife.jdbi.v2.sqlobject.customizers.RegisterMapperFactory;
import org.skife.jdbi.v2.sqlobject.mixins.Transactional;

import com.appirio.tech.core.api.v3.util.jdbi.TCBeanMapperFactory;
import com.appirio.tech.core.service.identity.representation.Email;

public abstract class EmailDAO implements Transactional<EmailDAO> {

	private static final Logger logger = Logger.getLogger(EmailDAO.class);

	public static final String EMAIL_COLUMNS =
		"e.user_id AS userId, e.email_id AS id, e.email_type_id AS typeId, e.address AS address, " +
		"e.status_id AS statusId, e.create_date AS createdAt, e.modify_date AS modifiedAt";

	@RegisterMapperFactory(TCBeanMapperFactory.class)
	@SqlQuery(
		"SELECT " + EMAIL_COLUMNS + " FROM email e WHERE user_id = :userId and email_type_id = :typeId"
	)
	protected abstract Email findEmail(@Bind("userId") long userId, @Bind("typeId") int typeId);
	
	@SqlQuery(
		"SELECT COUNT(user_id) FROM email WHERE LOWER(address)=LOWER(:email)"
	)
	protected abstract int countEmail(@Bind("email") String email);

	@SqlUpdate(
		"INSERT INTO email " +
		"(user_id, email_id, email_type_id, address, primary_ind, status_id) VALUES " +
		"(:userId, :emailId, 1, :email, 1, :statusId)")
	protected abstract int createEmail(@Bind("userId") long userId, @Bind("emailId") long emailId, @Bind("email") String email, @Bind("statusId") int statusId);

	@SqlUpdate(
		"UPDATE email SET " +
		"email_type_id = :e.typeId, address = :e.address, primary_ind = DECODE(:e.typeId, 1, 1, 0) " +
		"WHERE email_id = :e.id"
	)
	protected abstract int updateEmail(@BindBean("e") Email email); 
	
	@SqlUpdate(
		"UPDATE email SET status_id = 1 WHERE user_id = :userId AND email_type_id = 1"
	)
	protected abstract int activateEmail(@Bind("userId") long userId);

	
	public Email findPrimaryEmail(long userId) {
		logger.debug(String.format("finding primary email by userId(%s)", userId));
		return findEmail(userId, 1); // typeId 1: Primary, 2: Secondary 
	}
	
	public void update(Email email) {
		if(email==null)
			throw new IllegalArgumentException("email must be specified.");
		if(email.getId()==null)
			throw new IllegalArgumentException("email must have ID.");
		if(email.getAddress()==null)
			throw new IllegalArgumentException("email must have address.");
		
		logger.debug(String.format("updating email(%s) type: %s, address: %s", email.getId(), email.getType(), email.getAddress()));
		updateEmail(email);
	}
	
	public boolean emailExists(String email) {
		if(email==null)
			throw new IllegalArgumentException("email must be specified.");
		
		int count = countEmail(email);
		logger.debug(String.format("count of %s: %d", email, count));
		return count > 0;
	}

}
