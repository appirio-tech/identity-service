package com.appirio.tech.core.service.identity.util.idgen;

import org.skife.jdbi.v2.sqlobject.SqlQuery;
import org.skife.jdbi.v2.sqlobject.customizers.Define;
import org.skife.jdbi.v2.sqlobject.stringtemplate.UseStringTemplate3StatementLocator;

@UseStringTemplate3StatementLocator
public abstract class SequenceDAO {

	@SqlQuery(
			"SELECT <sequenceName>.nextval AS nextVal FROM systables WHERE tabid = 1"
		)
	public abstract Long nextVal(@Define("sequenceName") String sequenceName);
}
