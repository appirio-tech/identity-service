package com.appirio.tech.core.service.identity.util.event;

import static com.appirio.tech.core.service.identity.util.event.NotificationPayload.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.List;
import java.util.Map;

import org.junit.Test;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.service.identity.representation.User;
import com.appirio.tech.core.service.identity.util.event.NotificationPayload.ActivationPayload;

public class NotificationPayloadTest {

	@Test
	@SuppressWarnings("unchecked")
	public void testActivationPayload() {
		
		User user = new User();
		user.setId(new TCID(123456L));
		String redirectUrl = "http://www.topcoder.com/";
		
		// testee
		ActivationPayload testee = new ActivationPayload(user, redirectUrl);
		
		// test
		MailRepresentation result = testee.getMailRepresentation();
		
		// type
		assertEquals(ActivationPayload.TYPE, result.getNotificationType());
		
		// recipients
		List<Map<String, Object>> recipients = result.getRecipients();
		assertNotNull(recipients);
		assertEquals(1, recipients.size());
		Map<String, Object> recipient = recipients.get(0);
		assertEquals(user.getId(), recipient.get(RECIPIENT_KEY_ID));
		assertNotNull(recipient.get(RECIPIENT_KEY_PARAMS));
		
		// params
		Map<String, Object> params = (Map<String, Object>)recipient.get(RECIPIENT_KEY_PARAMS);
		assertEquals(user, params.get(ActivationPayload.PARAM_KEY_USER));
		assertEquals(redirectUrl, params.get(ActivationPayload.PARAM_KEY_REDIRECT_URL));
	}
	
	@SuppressWarnings("unchecked")
	@Test
	public void testPasswordResetPayload() {
		User user = new User();
		user.setId(new TCID(123456L));
		
		String resetToken = "RESET-TOKEN";
		int tokenExpirySeconds = 30 * 60;
		String urlPrefix = "URL-PREFIX";
		
		// testee
		PasswordResetPayload testee = spy(new PasswordResetPayload(user, resetToken, tokenExpirySeconds, urlPrefix));
		long ts = System.currentTimeMillis();
		doReturn(ts).when(testee).getCurrentTime();
		long expiryTime = ((long)tokenExpirySeconds * 1000L) + ts;
		String expiry = "00:49:44 EST on 2015-12-21";
		doReturn(expiry).when(testee).dateString(PasswordResetPayload.EXPIRY_DATE_FORMAT, PasswordResetPayload.EXPIRY_DATE_TZ, expiryTime);

		// test
		MailRepresentation result = testee.getMailRepresentation();

		// type
		assertEquals(PasswordResetPayload.TYPE, result.getNotificationType());
		
		// recipients
		List<Map<String, Object>> recipients = result.getRecipients();
		assertNotNull(recipients);
		assertEquals(1, recipients.size());
		Map<String, Object> recipient = recipients.get(0);
		assertEquals(user.getId(), recipient.get(RECIPIENT_KEY_ID));
		assertNotNull(recipient.get(RECIPIENT_KEY_PARAMS));
		
		// params
		Map<String, Object> params = (Map<String, Object>)recipient.get(RECIPIENT_KEY_PARAMS);
		assertEquals(user, params.get(PasswordResetPayload.PARAM_KEY_USER));
		assertEquals(resetToken, params.get(PasswordResetPayload.PARAM_KEY_TOKEN));
		assertEquals(expiry, params.get(PasswordResetPayload.PARAM_KEY_EXPIRY));
		assertEquals(urlPrefix, params.get(PasswordResetPayload.PARAM_KEY_URL_PREFIX));
		
		verify(testee).getCurrentTime();
		verify(testee).dateString(PasswordResetPayload.EXPIRY_DATE_FORMAT, PasswordResetPayload.EXPIRY_DATE_TZ, expiryTime);
	}
	
	@Test
	public void testWelcomePayload() {
		User user = new User();
		user.setId(new TCID(123456L));

		// testee
		WelcomePayload testee = new WelcomePayload(user);
		
		// test
		MailRepresentation result = testee.getMailRepresentation();

		// type
		assertEquals(WelcomePayload.TYPE, result.getNotificationType());
		
		// recipients
		List<Map<String, Object>> recipients = result.getRecipients();
		assertNotNull(recipients);
		assertEquals(1, recipients.size());
		Map<String, Object> recipient = recipients.get(0);
		assertEquals(user.getId(), recipient.get(RECIPIENT_KEY_ID));
		assertNotNull(recipient.get(RECIPIENT_KEY_PARAMS));
		
		// params
		@SuppressWarnings("unchecked")
		Map<String, Object> params = (Map<String, Object>)recipient.get(RECIPIENT_KEY_PARAMS);
		assertNotNull(params);
	}
}
