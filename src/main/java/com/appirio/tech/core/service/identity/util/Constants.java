/**
 * Copyright (C) 2017 Topcoder Inc., All Rights Reserved.
 */
package com.appirio.tech.core.service.identity.util;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Constants.
 * 
 * <p>
 * Version 1.1 - GROUP AND MEMBERSHIP MANAGEMENT API
 * - Added MSG_TEMPLATE_NOT_EXIST constant
 * </p>
 *
 * @author TCSCODER
 * @version 1.1
 */
public class Constants {

	public static final int MAX_LENGTH_EMAIL = 100;
	
	public static final int MAX_LENGTH_HANDLE = 15;

	public static final int MIN_LENGTH_HANDLE = 2;
	
    public static final int MAX_LENGTH_PASSWORD_V2 = 30;

    public static final int MIN_LENGTH_PASSWORD_V2 = 7;

    public static final int MAX_LENGTH_PASSWORD = 64;

    public static final int MIN_LENGTH_PASSWORD = 8;

	public static final int MAX_LENGTH_FIRST_NAME = 64;
	
	public static final int MAX_LENGTH_LAST_NAME = 64;

	public static final String ALPHABET_ALPHA_UPPER_EN = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	public static final String ALPHABET_ALPHA_LOWER_EN = "abcdefghijklmnopqrstuvwxyz";

	public static final String ALPHABET_ALPHA_EN = ALPHABET_ALPHA_LOWER_EN + ALPHABET_ALPHA_UPPER_EN;
	
	public static final String ALPHABET_WHITESPACE_EN = " \t\r\n";
	
	public static final String ALPHABET_DIGITS_EN = "0123456789";

	/*
    public static final String EMAIL_REGEX = "\\b(^[_A-Za-z0-9-]+(\\.[_A-Za-z0-9-]+)*@([A-Za-z0-9-])+((\\.com)"
            + "|(\\.net)|(\\.org)|(\\.info)|(\\.edu)|(\\.mil)|(\\.gov)|(\\.biz)|(\\.ws)|(\\.us)|(\\.tv)|(\\.cc)"
            + "|(\\.aero)|(\\.arpa)|(\\.coop)|(\\.int)|(\\.jobs)|(\\.museum)|(\\.name)|(\\.pro)|(\\.travel)|(\\.nato)"
            + "|(\\..{2,3})|(\\.([A-Za-z0-9-])+\\..{2,3}))$)\\b";
    */
    public static final String EMAIL_REGEX = "(^[\\+_A-Za-z0-9-]+(\\.[\\+_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,}$))";
    public static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);

    public static final Pattern LOWER_CASE_PATTERN = Pattern.compile("[a-z]");

    public static final Pattern UPPER_CASE_PATTERN = Pattern.compile("[A-Z]");
    
    public static final Pattern ALPHABET_PATTERN = Pattern.compile("[A-Za-z]");

    public static final Pattern SYMBOL_PATTERN = Pattern.compile("\\p{Punct}");

    public static final Pattern NUMBER_PATTERN = Pattern.compile("\\d");

	public final static String HANDLE_PUNCTUATION = "-_.{}[]";

	public final static String HANDLE_ALPHABET = ALPHABET_ALPHA_EN + ALPHABET_DIGITS_EN + HANDLE_PUNCTUATION;
	
	public static final int EMAIL_STATUS_ID_ACTIVE = 1;
	
	public static final int EMAIL_STATUS_ID_INACTIVE = 2;
	
	public static final String MSG_TEMPLATE_MANDATORY = "%s is required";
	
	public static final String MSG_TEMPLATE_INVALID = "%s is invalid";
	
	public static final String MSG_TEMPLATE_INVALID_MAX_LENGTH = "Maximum length of %s is %d";
	
	public static final String MSG_TEMPLATE_INVALID_MINMAX_LENGTH = "Length of %s in character should be between %d and %d";

	public static final String MSG_TEMPLATE_INVALID_HANDLE_LENGTH = String.format(MSG_TEMPLATE_INVALID_MINMAX_LENGTH, "Handle", MIN_LENGTH_HANDLE, MAX_LENGTH_HANDLE);
	
	public static final String MSG_TEMPLATE_INVALID_EMAIL_LENGTH = String.format(MSG_TEMPLATE_INVALID_MAX_LENGTH, "Email address", MAX_LENGTH_EMAIL);

	public static final String MSG_TEMPLATE_INVALID_HANDLE_CONTAINS_SPACE = "Handle may not contain a space";
	
	public static final String MSG_TEMPLATE_INVALID_HANDLE_CONTAINS_FORBIDDEN_CHAR = "Handle may contain only letters, numbers and " + HANDLE_PUNCTUATION;

	public static final String MSG_TEMPLATE_INVALID_HANDLE_CONTAINS_ONLY_PUNCTUATION = "Handle may not contain only punctuation.";

	public static final String MSG_TEMPLATE_INVALID_HANDLE_STARTS_WITH_ADMIN = "Please choose another handle, not starting with admin.";

	/**
	 * The message template for object does not exist.
	 */
	public static final String MSG_TEMPLATE_NOT_EXIST = "%s does not exist.";

	public static final String MSG_TEMPLATE_DUPLICATED = "'%s' is already existing.";
	
	public static final String MSG_TEMPLATE_DUPLICATED_HANDLE = "Handle '%s' has already been taken";

	public static final String MSG_TEMPLATE_UNSUPPORTED_PROVIDER = "Provider '%s' is not suppoerted";

	public static final String MSG_TEMPLATE_SOCIAL_PROFILE_IN_USE = "Social account has already been in use";

	public static final String MSG_TEMPLATE_USER_ALREADY_BOUND_WITH_PROVIDER = "User has already been bound with an account in the specified provider";

	public static final String MSG_TEMPLATE_SOCIAL_PROFILE_NOT_FOUND = "Social account does not exist";

	public static final String MSG_TEMPLATE_SSO_PROFILE_IN_USE = "SSO account already in use";

	public static final String MSG_TEMPLATE_INVALID_ID = String.format(MSG_TEMPLATE_INVALID, "ID");

	public static final String MSG_TEMPLATE_INVALID_HANDLE = String.format(MSG_TEMPLATE_INVALID, "Handle");
	
	public static final String MSG_TEMPLATE_INVALID_EMAIL = String.format(MSG_TEMPLATE_INVALID, "Email address");

	public static final String MSG_TEMPLATE_INVALID_COUNTRY = String.format(MSG_TEMPLATE_INVALID, "Country data");

	public static final String MSG_TEMPLATE_INVALID_COUNTRY_CODE = String.format(MSG_TEMPLATE_INVALID, "Country code");
	
	public static final String MSG_TEMPLATE_INVALID_COUNTRY_NAME = String.format(MSG_TEMPLATE_INVALID, "Country name");

	public static final String MSG_TEMPLATE_INVALID_STATUS = String.format(MSG_TEMPLATE_INVALID, "Status");

	public static final String MSG_TEMPLATE_DUPLICATED_EMAIL = "Email address '%s' has already been registered, please use another one.";

	public static final String MSG_TEMPLATE_INVALID_PASSWORD = "Password is too weak";
	
	public static final String MSG_TEMPLATE_INVALID_PASSWORD_LETTER = "Password must have at least a letter";

	public static final String MSG_TEMPLATE_INVALID_PASSWORD_NUMBER_SYMBOL = "Password must have at least a symbol or number";
	
	public static final String MSG_TEMPLATE_INVALID_CURRENT_PASSWORD = "Current password is not correct";

	public static final String MSG_TEMPLATE_RESET_TOKEN_ALREADY_ISSUED = "You have already requested the reset token. Please find it in your email inbox. If it's not there, please contact support@topcoder.com.";
	
	public static final String MSG_TEMPLATE_USER_NOT_FOUND = "User does not exist";
	
	public static final String MSG_TEMPLATE_PRIMARY_EMAIL_NOT_FOUND = "Primary email address has not been registered";
	
	public static final String MSG_TEMPLATE_INVALID_ACTIVATION_CODE = String.format(MSG_TEMPLATE_INVALID, "Activation code");

	public static final String MSG_TEMPLATE_USER_ALREADY_ACTIVATED = "User has been activated";

	public static final String MSG_TEMPLATE_EMAIL_ALREADY_ACTIVATED = "Email has been activated";

	public static final String MSG_TEMPLATE_EXPIRED_RESET_TOKEN = "Token is expired";
	
	public static final String MSG_TEMPLATE_INVALID_RESET_TOKEN = "Token is incorrect";
	
	public static final String MSG_TEMPLATE_NOT_ALLOWED_TO_RESET_PASSWORD = "User is not allowed to reset password";
	
	public static final String MSG_TEMPLATE_MISSING_UTMSOURCE = "utm_source should be provided";
	
	public static final String MSG_FATAL_ERROR = "Internal Server Error";
	
	public static final String REASON_INVALID_LENGTH = "INVALID_LENGTH";
	
	public static final String REASON_INVALID_FORMAT = "INVALID_FORMAT";
	
	public static final String REASON_INVALID_HANDLE = "INVALID_HANDLE";
	
	public static final String REASON_INVALID_EMAIL = "INVALID_EMAIL";

	public static final String REASON_ALREADY_TAKEN = "ALREADY_TAKEN";
	
	public static final String REASON_ALREADY_IN_USE = "ALREADY_IN_USE";

	public static String code(String msg) {
		if(msg==null)
			return null;
		String code = REASON_CODES.get(msg);
		if(code!=null)
			return code;
		
		for(Iterator<String> msgs = REASON_CODES.keySet().iterator(); msgs.hasNext();) {
			String m = msgs.next();
			if(!m.contains("%s"))
				continue;
			int p = 0;
			for(Iterator<String> tokens = Arrays.asList(m.split("%s")).iterator(); tokens.hasNext(); ) {
				String t = tokens.next();
				p = msg.indexOf(t, p);
				if(p<0)
					break;
				p += t.length();
			}
			if(p>-1)
				return REASON_CODES.get(m);
		}
		return null;
	}
	
	
	@SuppressWarnings("serial")
	public static final Map<String, String> REASON_CODES = new HashMap<String, String>() {{
		put(MSG_TEMPLATE_INVALID_HANDLE_LENGTH, REASON_INVALID_LENGTH);
		put(MSG_TEMPLATE_INVALID_HANDLE_CONTAINS_SPACE, REASON_INVALID_FORMAT);
		put(MSG_TEMPLATE_INVALID_HANDLE_CONTAINS_FORBIDDEN_CHAR, REASON_INVALID_FORMAT);
		put(MSG_TEMPLATE_INVALID_HANDLE_CONTAINS_ONLY_PUNCTUATION, REASON_INVALID_FORMAT);
		put(MSG_TEMPLATE_INVALID_HANDLE_STARTS_WITH_ADMIN, REASON_INVALID_HANDLE);
		put(MSG_TEMPLATE_INVALID_HANDLE, REASON_INVALID_HANDLE);
		put(MSG_TEMPLATE_DUPLICATED_HANDLE, REASON_ALREADY_TAKEN);
		put(MSG_TEMPLATE_INVALID_EMAIL_LENGTH, REASON_INVALID_LENGTH);
		put(MSG_TEMPLATE_INVALID_EMAIL, REASON_INVALID_EMAIL);
		put(MSG_TEMPLATE_DUPLICATED_EMAIL, REASON_ALREADY_TAKEN);
		put(MSG_TEMPLATE_SOCIAL_PROFILE_IN_USE, REASON_ALREADY_IN_USE);
		put(MSG_TEMPLATE_SSO_PROFILE_IN_USE, REASON_ALREADY_IN_USE);
	}};
}
