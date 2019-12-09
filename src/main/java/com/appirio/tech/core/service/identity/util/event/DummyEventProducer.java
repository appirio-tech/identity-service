package com.appirio.tech.core.service.identity.util.event;

import org.apache.log4j.Logger;

import com.appirio.eventsbus.api.client.EventProducer;
import com.appirio.eventsbus.api.client.exception.EmptyEventException;
import com.appirio.eventsbus.api.client.exception.EncodingEventException;

/* PENDING: COR-2015-11-16-P1 */
public class DummyEventProducer { //extends EventProducer {

	/*
	private static final Logger logger = Logger.getLogger(DummyEventProducer.class);
	
	@Override
	public void publish(String topic, Object payload) throws EmptyEventException, EncodingEventException {
		logger.info(String.format("[DummyEventProducer] received an event. topic: %s, payload: %s", topic, payload));
	}
	
	@Override
	public void close() {
	}
	*/	
}
