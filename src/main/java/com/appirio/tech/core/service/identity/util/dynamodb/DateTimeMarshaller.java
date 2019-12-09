package com.appirio.tech.core.service.identity.util.dynamodb;

import org.joda.time.DateTime;
import org.joda.time.format.ISODateTimeFormat;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMarshaller;

/**
 * Dynamodb marshaller for joda DateTime
 * 
 * @author james
 *
 */
public class DateTimeMarshaller implements DynamoDBMarshaller<DateTime> {

	@Override
	public String marshall(DateTime getterReturnResult) {
		if (getterReturnResult == null) {
			return null;
		}

		String dt = getterReturnResult.toString(ISODateTimeFormat.dateTime().withZoneUTC());
		return dt;
	}

	@Override
	public DateTime unmarshall(Class<DateTime> clazz, String obj) {
		if (obj == null) {
			return null;
		}
		return ISODateTimeFormat.dateTimeParser().parseDateTime(obj);
	}

}
