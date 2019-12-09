package com.appirio.tech.core.service.identity.util.event;

import javax.validation.constraints.NotNull;

import org.apache.log4j.Logger;

import com.appirio.eventsbus.api.client.EventProducer;
import com.fasterxml.jackson.annotation.JsonProperty;

public class EventSystemFactory {
	
	private static final Logger logger = Logger.getLogger(EventSystemFactory.class);

	private ProducerFactory producerFactory;
	
	@JsonProperty("producer")
	public ProducerFactory getProducerFactory() {
		return producerFactory;
	}

	@JsonProperty("producer")
	public void setProducerFactory(ProducerFactory producerFactory) {
		this.producerFactory = producerFactory;
	}

	public static class ProducerFactory {
		
		@NotNull
		private String type;

		public String getType() {
			return type;
		}

		public void setType(String type) {
			this.type = type;
		}
		
		public EventProducer createProducer() {
			
			if("dummy".equals(type)) {
				logger.info("Creating DummyEventProducer");
				//COR-2015-11-16-P1
				//return new DummyEventProducer();
				return null;
			}
			else if("kafka".equals(type)) {
				logger.info("Creating EventProducer");
				return EventProducer.getInstance();
			}
			throw new IllegalArgumentException("Unknown EventProducer type: "+type);
		}
	}
}
