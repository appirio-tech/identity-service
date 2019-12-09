package com.appirio.tech.core.service.identity.util.dynamodb;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMarshaller;
import com.amazonaws.util.json.Jackson;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Base class that marshalls/unmarshalls JSON
 * 
 * @author james
 *
 * @param <T> The class to marshal/unmarshal
 */
public abstract class BaseJsonMarshaller<T> implements DynamoDBMarshaller<T> {

	private static final Logger logger = LoggerFactory.getLogger(BaseJsonMarshaller.class);

	// we need this mapper because of it's handling of joda datetimes
	private static ObjectMapper mapper = Jackson.getObjectMapper();
	
	protected BaseJsonMarshaller() {
		
	}
	
	public static void setMapper(ObjectMapper mapper) {
		BaseJsonMarshaller.mapper = mapper;
	}

	@Override
	public String marshall(T object) {
		if (object == null) {
			return null;
		}
		try {
			return mapper.writeValueAsString(object);
		} catch (JsonProcessingException e) {
			logger.error("Unable to marshall object: {}", e.getMessage());
			throw new RuntimeException(e);
		}
	}

	@Override
	public T unmarshall(Class<T> clazz, String json) {
		if (json == null) {
			return null;
		}
		try {
			return mapper.readValue(json, clazz);
		} catch (Exception e) {
			logger.error("Unable to unmarshall object: {}. JSON={}", e.getMessage(), json);
			throw new RuntimeException(e);
		}
	}

	
}
