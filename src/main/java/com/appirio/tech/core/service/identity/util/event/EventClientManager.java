package com.appirio.tech.core.service.identity.util.event;

import com.appirio.eventsbus.api.client.EventProducer;
import io.dropwizard.lifecycle.Managed;

/**
 * Created by ramakrishnapemmaraju on 9/1/15.
 */
public class EventClientManager implements Managed {

    private final EventProducer producer;

    public EventClientManager(EventProducer producer) {
        this.producer = producer;
    }

    @Override
    public void start() throws Exception {

    }

    @Override
    public void stop() throws Exception {
        producer.close();
    }
}
