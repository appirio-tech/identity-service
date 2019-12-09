package com.appirio.tech.core.service.identity.util.event;

import java.util.List;
import java.util.Map;

/**
 * Created by ramakrishnapemmaraju on 11/30/15.
 */
public class MailRepresentation {

    List<Map<String, Object>> recipients;
    String notificationType;

    public List<Map<String, Object>> getRecipients() {
        return recipients;
    }

    public void setRecipients(List<Map<String, Object>> recipients) {
        this.recipients = recipients;
    }

    public String getNotificationType() {
        return notificationType;
    }

    public void setNotificationType(String notificationType) {
        this.notificationType = notificationType;
    }
}
