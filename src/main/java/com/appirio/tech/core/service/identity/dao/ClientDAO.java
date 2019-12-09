package com.appirio.tech.core.service.identity.dao;

import java.util.List;

import org.apache.log4j.Logger;
import org.skife.jdbi.v2.sqlobject.Bind;
import org.skife.jdbi.v2.sqlobject.SqlQuery;
import org.skife.jdbi.v2.sqlobject.customizers.RegisterMapperFactory;
import org.skife.jdbi.v2.sqlobject.mixins.Transactional;
import org.skife.jdbi.v2.sqlobject.stringtemplate.UseStringTemplate3StatementLocator;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.dao.DaoBase;
import com.appirio.tech.core.api.v3.request.FieldSelector;
import com.appirio.tech.core.api.v3.request.QueryParameter;
import com.appirio.tech.core.api.v3.util.jdbi.TCBeanMapperFactory;
import com.appirio.tech.core.service.identity.representation.Client;
import com.appirio.tech.core.service.identity.representation.Role;


@UseStringTemplate3StatementLocator
@RegisterMapperFactory(TCBeanMapperFactory.class)
public abstract class ClientDAO implements DaoBase<Client>, Transactional<ClientDAO> {

	@SuppressWarnings("unused")
	private static final Logger logger = Logger.getLogger(ClientDAO.class);

	@SqlQuery(
		"SELECT " +
		"id, client_id AS clientId, name, redirect_uri AS redirectUri, " +
		"secret, createdBy, createdAt, modifiedBy, modifiedAt " + 
		"FROM client WHERE client_id = :clientId")
	public abstract Client findClient(@Bind("clientId") String clientId);
	
	
	@Override
	public List<Client> populate(QueryParameter query) throws Exception {
		return null;
	}

	@Override
	public Client populateById(FieldSelector selector, TCID recordId) throws Exception {
		return null;
	}

	@Override
	public TCID insert(Client obj) throws Exception {
		return null;
	}

	@Override
	public TCID update(Client obj) throws Exception {
		return null;
	}

	@Override
	public void delete(TCID id) throws Exception {
	}
}
