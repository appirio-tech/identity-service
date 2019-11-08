package com.appirio.tech.core.service.identity.util.event;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

import com.appirio.tech.core.service.identity.representation.User;

public abstract class NotificationPayload {

	public static final String RECIPIENT_KEY_ID = "id";

	public static final String RECIPIENT_KEY_PARAMS = "params";

	public abstract MailRepresentation getMailRepresentation();

	public static class ActivationCodeOnlyPayload extends ActivationPayload{
		
		public static final String TYPE = "useractivation-codeonly";
		
		public ActivationCodeOnlyPayload(User user, String redirectUrl) {
			super(user, redirectUrl);
		}
		
		@Override
		public MailRepresentation getMailRepresentation() {
			MailRepresentation mail = super.getMailRepresentation();
			mail.setNotificationType(TYPE); // replace notification type
			return mail;
		}
	}
	
	public static class ActivationPayload extends NotificationPayload {
		
		public static final String TYPE = "useractivation";

		public static final String PARAM_KEY_USER = "user";

		public static final String PARAM_KEY_REDIRECT_URL = "redirectUrl";

		private User user;
		
		private String redirectUrl;
		
		public ActivationPayload(User user, String redirectUrl) {
			this.user = user;
			this.redirectUrl = redirectUrl;
		}

		@Override
		public MailRepresentation getMailRepresentation() {
			ArrayList<Map<String, Object>> recipients = new ArrayList<>();
			Map<String, Object> map = new HashMap<>();
			map.put(RECIPIENT_KEY_ID, user.getId());
			Map<String, Object> paramMap = new HashMap<>();
			paramMap.put(PARAM_KEY_USER, user);
			paramMap.put(PARAM_KEY_REDIRECT_URL, redirectUrl);
			map.put(RECIPIENT_KEY_PARAMS, paramMap);
			recipients.add(map);

			MailRepresentation mail = new MailRepresentation();
			mail.setNotificationType(TYPE);
			mail.setRecipients(recipients);
			return mail;
		}
	}
	
	public static class PasswordResetPayload extends NotificationPayload {
		
		public static final String TYPE = "userpasswordreset";

		public static final String PARAM_KEY_USER = "user";

		public static final String PARAM_KEY_TOKEN = "token";

		public static final String PARAM_KEY_EXPIRY = "expiry";

		public static final String PARAM_KEY_URL_PREFIX = "resetPassworUrlPrefix";

		public static final String EXPIRY_DATE_FORMAT = "HH:mm:ss z 'on' yyyy-MM-dd";
		
		public static final String EXPIRY_DATE_TZ = "America/New_York";

		private User user;
		
		private String resetToken;
		
		private int tokenExpirySeconds;
		
		private String resetPassworUrlPrefix;
		
		
		public PasswordResetPayload(User user, String resetToken, int tokenExpirySeconds, String resetPassworUrlPrefix) {
			this.user = user;
			this.resetToken = resetToken;
			this.tokenExpirySeconds = tokenExpirySeconds;
			this.resetPassworUrlPrefix = resetPassworUrlPrefix;
		}

		@Override
		public MailRepresentation getMailRepresentation() {
			String expiryDate = dateString(EXPIRY_DATE_FORMAT, EXPIRY_DATE_TZ, getCurrentTime()+(tokenExpirySeconds*1000L));
			ArrayList<Map<String, Object>> recipients = new ArrayList<>();
			Map<String, Object> map = new HashMap<>();
			map.put(RECIPIENT_KEY_ID, user.getId());
			Map<String, Object> paramMap = new HashMap<>();
			paramMap.put(PARAM_KEY_USER, user);
			paramMap.put(PARAM_KEY_TOKEN, resetToken);
			paramMap.put(PARAM_KEY_EXPIRY, expiryDate);
			paramMap.put(PARAM_KEY_URL_PREFIX, resetPassworUrlPrefix);
			
			map.put(RECIPIENT_KEY_PARAMS, paramMap);
			recipients.add(map);
			
			MailRepresentation mail = new MailRepresentation();
			mail.setNotificationType(TYPE);
			mail.setRecipients(recipients);
			return mail;
		}

		protected long getCurrentTime() {
			return System.currentTimeMillis();
		}
		
		protected String dateString(String format, String timezoneId, long time) {
			SimpleDateFormat fmt = new SimpleDateFormat(format);
			fmt.setTimeZone(TimeZone.getTimeZone(timezoneId));
			return fmt.format(new Date(time));
		}
	}
	
	public static class WelcomePayload extends NotificationPayload {
		
		public static final String TYPE = "welcome";

		private User user;
		
		public WelcomePayload(User user) {
			this.user = user;
		}
		
		@Override
		public MailRepresentation getMailRepresentation() {
			ArrayList<Map<String, Object>> recipients = new ArrayList<>();
			Map<String, Object> map = new HashMap<>();
			map.put(RECIPIENT_KEY_ID, user.getId());
			Map<String, Object> paramMap = new HashMap<>();
			//paramMap.put("user", user);
			map.put(RECIPIENT_KEY_PARAMS, paramMap);
			recipients.add(map);

			MailRepresentation mail = new MailRepresentation();
			mail.setNotificationType(TYPE);
			mail.setRecipients(recipients);
			return mail;
		}
	}	
}
