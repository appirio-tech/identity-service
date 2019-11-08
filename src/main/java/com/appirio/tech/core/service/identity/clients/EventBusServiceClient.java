package com.appirio.tech.core.service.identity.clients;

import com.appirio.clients.BaseClient;
import com.appirio.clients.BaseClientConfiguration;
import com.appirio.tech.core.service.identity.M2mAuthConfiguration;
import com.appirio.tech.core.service.identity.util.Utils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.jetty.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * The client to communicate with TC Bus With the REST API.
 * It's add in Fast 48hrs!! Topcoder Identity Service - Support Event Bus Publishing v1.0
 *
 * @author TCCoder
 * @version 1.0
 *
 */
public class EventBusServiceClient extends BaseClient {
    /**
     * The logger for this class
     */
    private final static Logger LOGGER = LoggerFactory.getLogger(EventBusServiceClient.class);

    private M2mAuthConfiguration m2mAuthConfiguration;
    /**
     * Constructor
     *
     * @param client the Jersey client
     * @param config the configuration
     */
    public EventBusServiceClient(Client client, BaseClientConfiguration config, M2mAuthConfiguration m2mAuthConfiguration) {
        super(client, config);

        this.m2mAuthConfiguration = m2mAuthConfiguration;
    }

    /**
     * Fire event
     *
     * @param eventMessage the eventMessage to use
     */
    public void fireEvent(EventMessage eventMessage) {
        try {
            String url = this.config.getEndpoint();
            WebTarget target = this.client.target(url);
            final Invocation.Builder request = target.request(MediaType.APPLICATION_JSON_TYPE);
            String authToken = Utils.generateAuthToken(m2mAuthConfiguration);

            eventMessage.setOriginator(this.config.getAdditionalConfiguration().get("originator"));
            eventMessage.setTopic(this.config.getAdditionalConfiguration().get("topic"));
            Response response = request.header("Authorization", "Bearer " + authToken).post(Entity.entity(eventMessage.getData(), MediaType.APPLICATION_JSON_TYPE));

            LOGGER.info("Fire event {}", new ObjectMapper().writer().writeValueAsString(eventMessage));
            if (response.getStatusInfo().getStatusCode() != HttpStatus.OK_200 &&  response.getStatusInfo().getStatusCode()!= HttpStatus.NO_CONTENT_204) {
                LOGGER.error("Unable to fire the event: {}", response);
            }
        }  catch (Exception e) {
            LOGGER.error("Failed to fire the event: {}", e);
        }
    }
}