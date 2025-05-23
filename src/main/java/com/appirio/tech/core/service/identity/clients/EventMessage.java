package com.appirio.tech.core.service.identity.clients;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TimeZone;

/**
 * Represents the EventMessage model
 *
 * It's add in Fast 48hrs!! Topcoder Identity Service - Support Event Bus Publishing v1.0
 *
 * @author TCCoder
 * @version 1.0
 *
 */
public class EventMessage {
    /**
     * The DATE_FORMAT field
     */
    public static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

    /**
     * The fields contains the data of the message
     */
    private Map<String, Object> fields = new LinkedHashMap<>();
    /**
     * Set topic
     *
     * @param topic the topic to use
     * @return the EventMessage result
     */
    public EventMessage setTopic(String topic) {
        fields.put("topic", topic);
        return this;
    }
    /**
     * Set originator
     *
     * @param originator the originator to use
     * @return the EventMessage result
     */
    public EventMessage setOriginator(String originator) {
        fields.put("originator", originator);
        return this;
    }
    /**
     * Set mime type
     *
     * @param mimeType the mimeType to use
     * @return the EventMessage result
     */
    public EventMessage setMimeType(String mimeType) {
        fields.put("mime-type", mimeType);
        return this;
    }
    /**
     * Set timestamp
     *
     * @param timestamp the timestamp to use
     * @return the EventMessage result
     */
    public EventMessage setTimestamp(Date timestamp) {
        DateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT);
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        fields.put("timestamp", dateFormat.format(timestamp));
        return this;
    }
    /**
     * Set payload
     * This method is useful if users want to set an entity(or map) directly as the payload.
     *
     * @param payload the payload to use
     * @return the EventMessage result
     */
    public EventMessage setPayload(Object payload) {
        fields.put("payload", payload);
        return this;
    }
    /**
     * Set payload with key and value.
     *
     * @param key the key to use
     * @param value the value
     * @return the EventMessage result
     * @throws java.lang.ClassCastException if the payload object can not be casted to Map<Sring, Object>
     */
    public EventMessage setPayload(String key, Object value) {
        // throw java.lang.ClassCastException if the fields.get("payload") is not of Map<String, Object> type
        Map<String, Object> payload = (Map<String, Object>) fields.get("payload");
        if (payload == null) {
            payload = new LinkedHashMap<>();
            fields.put("payload", payload);
        }
        payload.put(key, value);
        return this;
    }
    /**
     * Get data
     *
     * @return the Map<String,Object> result
     */
    public Map<String, Object> getData() {
        Map<String, Object> copy = new LinkedHashMap<>(this.fields);
        return copy;
    }

    /**
     * Get default EventMessage
     *
     * @return the EventMessage result
     */
    public static EventMessage getDefault() {
        EventMessage msg = new EventMessage();
        // user can always change the topic with the default one by calling setTopic(..)
        msg.setTopic("notifications.kafka.queue.java.test").setMimeType("application/json").setTimestamp(new Date()).setOriginator("identity.service");
        return msg;
    }
}