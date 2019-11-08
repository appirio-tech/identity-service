package com.appirio.tech.core.service.identity.util.dynamodb;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMarshaller;

/**
 * Marshalls/unmarshalls an opaque JSON string to/from a Java Object.
 * 
 * @author james
 *
 */
public class JsonObjectMarshaller extends BaseJsonMarshaller<Object> implements DynamoDBMarshaller<Object> {

	// everything handled by base class
	public JsonObjectMarshaller() {
		
	}
	

}
