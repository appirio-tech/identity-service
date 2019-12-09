package com.appirio.tech.core.service.identity.util.dynamodb;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMarshaller;
import com.appirio.tech.core.api.v3.TCID;

public class TCIDMarshaller implements DynamoDBMarshaller<TCID>{

	@Override
	public String marshall(TCID id) {
		return id == null ? null : id.toString();
	}

	@Override
	public TCID unmarshall(Class<TCID> clazz, String id) {
		return id == null ? null : new TCID(id);
	}

}
