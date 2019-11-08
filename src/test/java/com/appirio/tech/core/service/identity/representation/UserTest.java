package com.appirio.tech.core.service.identity.representation;

import static com.appirio.tech.core.service.identity.util.Constants.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

public class UserTest {

	@Test
	public void testGetProfile() {
		
		// testee
		User user = new User();

		// data1
		UserProfile profile = new UserProfile();
		List<UserProfile> profiles = new ArrayList<UserProfile>();
		profiles.add(profile);

		// test1
		user.setProfiles(profiles);
		UserProfile result = user.getProfile();
		assertEquals(profile, result);
		
		// data2
		@SuppressWarnings("serial")
		List<UserProfile> profiles2 = new ArrayList<UserProfile>(){{ add(new UserProfile()); add(new UserProfile()); }};
		
		// test2
		user.setProfiles(profiles2);
		UserProfile result2 = user.getProfile();
		assertEquals(profiles2.get(0), result2);
		
		// test3
		user.getProfiles().clear(); // profiles == empty
		assertNull(user.getProfile());
		
		// test4
		user.setProfiles(null); // profiles == null
		assertNull(user.getProfile());		
	}
	
	
	@Test
	public void testValidate() {
		User user = new User();
		
		// Create Mock with dummy validators.
		User mock = spy(user);
		
		doReturn(null).when(mock).validateHandle();
		doReturn(null).when(mock).validateEmail();
		doReturn(null).when(mock).validateFirstName();
		doReturn(null).when(mock).validateLastName();
		doReturn(null).when(mock).validatePassoword();
		
		// test
		assertNull(mock.validate());
		
		// verifying that all validators are invoked.
		verify(mock).validate();
		verify(mock).validateHandle();
		verify(mock).validateEmail();
		verify(mock).validateFirstName();
		verify(mock).validateLastName();
		verify(mock).validatePassoword();
	}
	
	@Test
	public void testValidateName() {

		User testee = new User();
		
		// First Name
		assertNull("First name should not be mandatory", testee.validateFirstName());
		testee.setFirstName("");
		assertNull("First name should not be mandatory", testee.validateFirstName());

		testee.setFirstName(genText(MAX_LENGTH_FIRST_NAME));
		assertNull("First name should receive "+MAX_LENGTH_FIRST_NAME+" length string.",
				testee.validateFirstName());
		
		testee.setFirstName(genText(MAX_LENGTH_FIRST_NAME+1));
		assertEquals(
				String.format(MSG_TEMPLATE_INVALID_MAX_LENGTH, "first name", MAX_LENGTH_FIRST_NAME),
				testee.validateFirstName());
		
		
		// Last Name
		assertNull("Last name should not be mandatory", testee.validateLastName());
		testee.setLastName("");
		assertNull("Last name should not be mandatory", testee.validateLastName());

		testee.setLastName(genText(MAX_LENGTH_LAST_NAME));
		assertNull("Last name should receive "+MAX_LENGTH_LAST_NAME+" length string.",
				testee.validateLastName());
		
		testee.setLastName(genText(MAX_LENGTH_LAST_NAME+1));
		assertEquals(
				String.format(MSG_TEMPLATE_INVALID_MAX_LENGTH, "last name", MAX_LENGTH_LAST_NAME),
				testee.validateLastName());
		
	}
	
	@Test
	public void testValidateHandle() {
		
		User testee = new User();

		// Mandatory
		assertEquals(
				String.format(MSG_TEMPLATE_MANDATORY, "Handle"),
				testee.validateHandle());
		testee.setHandle("");
		assertEquals(
				String.format(MSG_TEMPLATE_MANDATORY, "Handle"),
				testee.validateHandle());
		
		// Length
		testee.setHandle(genText(MIN_LENGTH_HANDLE));
		assertNull(testee.validateHandle());
		
		testee.setHandle(genText(MAX_LENGTH_HANDLE));
		assertNull(testee.validateHandle());
		
		testee.setHandle(genText(MAX_LENGTH_HANDLE+1));
		assertEquals(
				MSG_TEMPLATE_INVALID_HANDLE_LENGTH,
				testee.validateHandle());
		testee.setHandle(genText(MIN_LENGTH_HANDLE-1));
		assertEquals(
				MSG_TEMPLATE_INVALID_HANDLE_LENGTH,
				testee.validateHandle());

		// Contains blank
		String handle = genText(MIN_LENGTH_HANDLE) + " " + genText(MAX_LENGTH_HANDLE-(MIN_LENGTH_HANDLE+1));
		assertTrue(handle.length() <= MAX_LENGTH_HANDLE);
		testee.setHandle(handle);
		assertEquals(
				MSG_TEMPLATE_INVALID_HANDLE_CONTAINS_SPACE,
				testee.validateHandle());
		
		// Contains forbidden char
		String[] INVALID_CHARS = "!\"#$%&'()='^~\\|@`;+:*,<>/?".split("");
		for(int i=0; i<INVALID_CHARS.length; i++) {
			if(INVALID_CHARS[i].length()==0)
				continue;
			handle = genText(MIN_LENGTH_HANDLE) + INVALID_CHARS[i];
			assertTrue(handle.length() <= MAX_LENGTH_HANDLE);
			testee.setHandle(handle);
			assertEquals(
					MSG_TEMPLATE_INVALID_HANDLE_CONTAINS_FORBIDDEN_CHAR,
					testee.validateHandle());
		}
		
		// Contains only punctuation
		handle = HANDLE_PUNCTUATION;
		assertTrue(handle.length() >= MIN_LENGTH_HANDLE);
		assertTrue(handle.length() <= MAX_LENGTH_HANDLE);
		testee.setHandle(handle);
		assertEquals(
				MSG_TEMPLATE_INVALID_HANDLE_CONTAINS_ONLY_PUNCTUATION,
				testee.validateHandle());
		
		// Starts with "admin"
		String[] ADMIN_PATTERNS = new String[]{
			"admin","Admin","ADMIN","aDmin"
		};
		for(int i=0; i<ADMIN_PATTERNS.length; i++) {
			if(ADMIN_PATTERNS[i].length()==0)
				continue;
			handle = ADMIN_PATTERNS[i] + genText(MIN_LENGTH_HANDLE);
			assertTrue(handle.length() <= MAX_LENGTH_HANDLE);
			testee.setHandle(handle);
			assertEquals(
					MSG_TEMPLATE_INVALID_HANDLE_STARTS_WITH_ADMIN,
					testee.validateHandle());
		}
	}
	
	@Test
	public void testValidateEmail() {
		
		User testee = new User();
		
		// Mandatory
		assertEquals(
				String.format(MSG_TEMPLATE_MANDATORY, "Email address"),
				testee.validateEmail());
		testee.setEmail("");
		assertEquals(
				String.format(MSG_TEMPLATE_MANDATORY, "Email address"),
				testee.validateEmail());

		String suffix = "@example.com";
		String prefix = genText(MAX_LENGTH_EMAIL-suffix.length());
		String testEmail = prefix+suffix;
		assertEquals(MAX_LENGTH_EMAIL, testEmail.length());
		testee.setEmail(testEmail);
		assertNull("Email address should receive "+MAX_LENGTH_EMAIL+" length string.",
				testee.validateEmail());

		testee.setEmail(genText(MAX_LENGTH_EMAIL+1));
		assertEquals(
				MSG_TEMPLATE_INVALID_EMAIL_LENGTH,
				testee.validateEmail());
	}
	
	@Test
	public void testValidatePassoword() {
		User testee = new User();
		
		// Mandatory
		assertEquals(
				String.format(MSG_TEMPLATE_MANDATORY, "Password"),
				testee.validatePassoword());
		Credential cred = new Credential();
		testee.setCredential(cred);
		assertEquals(
				String.format(MSG_TEMPLATE_MANDATORY, "Password"),
				testee.validatePassoword());
		cred.setPassword("");
		assertEquals(
				String.format(MSG_TEMPLATE_MANDATORY, "Password"),
				testee.validatePassoword());

		// Min length
		String letter = "a";
		String num = "1";
		String letAndNum = letter+num;
		String passwd = genText(MIN_LENGTH_PASSWORD-letAndNum.length()) + letAndNum;
		testee.getCredential().setPassword(passwd);
		assertNull(testee.validatePassoword());
		
		passwd = genText(MIN_LENGTH_PASSWORD-1-letAndNum.length()) + letAndNum;
		testee.getCredential().setPassword(passwd);
		String msg = String.format(MSG_TEMPLATE_INVALID_MINMAX_LENGTH, "password", MIN_LENGTH_PASSWORD, MAX_LENGTH_PASSWORD); 
		assertEquals(msg, testee.validatePassoword());
		
		// Max length
		passwd = genText(MAX_LENGTH_PASSWORD-letAndNum.length()) + letAndNum;
		testee.getCredential().setPassword(passwd);
		assertNull(testee.validatePassoword());
		
		passwd = genText(MAX_LENGTH_PASSWORD+1-letAndNum.length()) + letAndNum;
		testee.getCredential().setPassword(passwd);
		assertEquals(msg, testee.validatePassoword());
		
		// Contains a letter
		passwd = genText(MIN_LENGTH_PASSWORD, '1');
		testee.getCredential().setPassword(passwd);
		assertEquals(MSG_TEMPLATE_INVALID_PASSWORD_LETTER, testee.validatePassoword());

		testee.getCredential().setPassword(passwd+letter);
		assertNull(testee.validatePassoword());
		

		// Contains a number or symbol
		passwd = genText(MIN_LENGTH_PASSWORD);
		testee.getCredential().setPassword(passwd);
		assertEquals(MSG_TEMPLATE_INVALID_PASSWORD_NUMBER_SYMBOL, testee.validatePassoword());
		
		testee.getCredential().setPassword(passwd+num);
		assertNull(testee.validatePassoword());

		testee.getCredential().setPassword(passwd+"?");
		assertNull(testee.validatePassoword());

		// password can contain space
		passwd = genText(MIN_LENGTH_PASSWORD) + " " + letAndNum;
		testee.getCredential().setPassword(passwd);
		assertNull(testee.validatePassoword());
	}
	
	@Test
	public void testValidatePassoword_V2() {
		User testee = new User();
		testee.passwordValidator = new User.PasswordValidatorV2();

		// Mandatory
		assertEquals(
				String.format(MSG_TEMPLATE_MANDATORY, "Password"),
				testee.validatePassoword());
		Credential cred = new Credential();
		testee.setCredential(cred);
		assertEquals(
				String.format(MSG_TEMPLATE_MANDATORY, "Password"),
				testee.validatePassoword());
		cred.setPassword("");
		assertEquals(
				String.format(MSG_TEMPLATE_MANDATORY, "Password"),
				testee.validatePassoword());

		// Min length
		String sym = "?", num = "1";
		String symNum = sym + num;
		String passwd = genText(MIN_LENGTH_PASSWORD_V2-symNum.length()) + symNum;
		assertEquals(MIN_LENGTH_PASSWORD_V2, passwd.length());
		testee.getCredential().setPassword(passwd);
		assertNull(testee.validatePassoword());
		
		testee.getCredential().setPassword(
				genText(MIN_LENGTH_PASSWORD_V2-1-symNum.length()) + symNum);
		assertEquals(
				String.format(MSG_TEMPLATE_INVALID_MINMAX_LENGTH, "password", MIN_LENGTH_PASSWORD_V2, MAX_LENGTH_PASSWORD_V2),
				testee.validatePassoword());

		// Max length
		passwd = genText(MAX_LENGTH_PASSWORD_V2-symNum.length()) + symNum;
		assertEquals(MAX_LENGTH_PASSWORD_V2, passwd.length());
		testee.getCredential().setPassword(passwd);
		assertNull(testee.validatePassoword());

		testee.getCredential().setPassword(
				genText(MAX_LENGTH_PASSWORD_V2+1-symNum.length()) + symNum);
		assertEquals(
				String.format(MSG_TEMPLATE_INVALID_MINMAX_LENGTH, "password", MIN_LENGTH_PASSWORD_V2, MAX_LENGTH_PASSWORD_V2),
				testee.validatePassoword());

		// Weakness
		String cap = "A";
		String[] WEAK_PASSWD_PATTERNS = new String[] {
				genText(MIN_LENGTH_PASSWORD_V2),
				genText(MIN_LENGTH_PASSWORD_V2).toLowerCase() + sym,
				genText(MIN_LENGTH_PASSWORD_V2).toLowerCase() + num,
				genText(MIN_LENGTH_PASSWORD_V2).toLowerCase() + cap,
				genText(MIN_LENGTH_PASSWORD_V2).toUpperCase() + sym,
				genText(MIN_LENGTH_PASSWORD_V2).toUpperCase() + num,
				genText(MIN_LENGTH_PASSWORD_V2).toUpperCase() + cap.toLowerCase(),
				
		};
		for(int i=0; i<WEAK_PASSWD_PATTERNS.length; i++) {
			testee.getCredential().setPassword(WEAK_PASSWD_PATTERNS[i]);
			assertEquals(MSG_TEMPLATE_INVALID_PASSWORD, testee.validatePassoword());
		}
		
		String[] STRONG_PASSWD_PATTERNS = new String[] {
				genText(MIN_LENGTH_PASSWORD_V2).toLowerCase() + sym + num,
				genText(MIN_LENGTH_PASSWORD_V2).toLowerCase() + sym + cap,
				genText(MIN_LENGTH_PASSWORD_V2).toLowerCase() + num + cap,
				genText(MIN_LENGTH_PASSWORD_V2).toUpperCase() + sym + num,
				genText(MIN_LENGTH_PASSWORD_V2).toUpperCase() + sym + cap.toLowerCase(),
				genText(MIN_LENGTH_PASSWORD_V2).toUpperCase() + num + cap.toLowerCase(),
		};
		for(int i=0; i<STRONG_PASSWD_PATTERNS.length; i++) {
			testee.getCredential().setPassword(STRONG_PASSWD_PATTERNS[i]);
			assertNull(testee.validatePassoword());
		}
	}
	
	@Test
	public void testChangeUserActivationStatus() {
		User testee = new User();
		
		// Initial status
		assertEquals(false, testee.isActive());
		assertNull(testee.getStatus());
		
		// Activated
		testee.setActive(true);
		assertEquals(true, testee.isActive());
		assertEquals(User.INTERNAL_STATUS_ACTIVE, testee.getStatus());
		
		// In-activated by changing status
		testee.setStatus(User.INTERNAL_STATUS_UNVERIFIED);
		assertEquals(false, testee.isActive());
		assertEquals(User.INTERNAL_STATUS_UNVERIFIED, testee.getStatus());
		
		// Activated by changing status
		testee.setStatus(User.INTERNAL_STATUS_ACTIVE);
		assertEquals(true, testee.isActive());
		assertEquals(User.INTERNAL_STATUS_ACTIVE, testee.getStatus());

		// In-activated
		testee.setActive(false);
		assertEquals(false, testee.isActive());
		assertEquals(User.INTERNAL_STATUS_UNVERIFIED, testee.getStatus());

		testee.setStatus(null);
		assertEquals(false, testee.isActive());
		assertNull(testee.getStatus());
	}
	
	@Test
	public void testChangeEmailActivationStatus() {
		
		User testee = new User();
		
		assertNull("emailStatus should be null.", testee.getEmailStatus());
		assertFalse("isEmailActive should be false.", testee.isEmailActive());
		
		testee.setEmailStatus(User.INTERNAL_EMAIL_STATUS_ACTIVE);
		assertEquals(User.INTERNAL_EMAIL_STATUS_ACTIVE, (int)testee.getEmailStatus());
		assertTrue("isEmailActive should be true.", testee.isEmailActive());
		
		testee.setEmailStatus(0);
		assertEquals(0, (int)testee.getEmailStatus());
		assertFalse("isEmailActive should be false.", testee.isEmailActive());
	}

	@Test
	public void testIsReferralProgramCampaign() {
		User testee = new User();

		assertNull(testee.getUtmCampaign());
		assertFalse(testee.isReferralProgramCampaign());

		testee.setUtmCampaign("ReferralProgram");
		assertTrue(testee.isReferralProgramCampaign());

		testee.setUtmCampaign("AnotherCampaign");
		assertFalse(testee.isReferralProgramCampaign());
	}

	public static String genText(int len) {
		return genText(len, 'a');
	}
	public static String genText(int len, char c) {
		if(len<=0)
			return "";
		StringBuilder sb = new StringBuilder();
		for(int i=0;i<len;i++)
			sb.append(c);
		return sb.toString();
	}

}
