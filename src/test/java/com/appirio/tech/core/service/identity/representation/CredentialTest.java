package com.appirio.tech.core.service.identity.representation;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.HashMap;

import org.junit.Before;
import org.junit.Test;

import com.appirio.tech.core.service.identity.util.Utils;

public class CredentialTest {

	@Before
	@SuppressWarnings("serial")
	public void beforeEachTest() {
		// setup: configuring default-password and hash-key
		String defaultPassword = "DEFAULT_PASSOWORD";
		String hashKey = "HASH_KEY";
		Utils.setApplicationContext(
			new HashMap<String, Object>() {
				{ put(Utils.CONTEXT_KEY_DEFAULT_PASSWORD, defaultPassword);
				  put(Utils.CONTEXT_KEY_PASSWORD_HASH, hashKey); }
			}
		);
	}
	@Test
	public void testHasPassword_FalseWhenPasswordIsStillDefault() throws Exception {
		boolean isDefaultPassword = true;
		testHasPassword(isDefaultPassword);
	}
	
	@Test
	public void testHasPassword_TrueWhenPasswordIsNotDefault() throws Exception {
		boolean isDefaultPassword = false;
		testHasPassword(isDefaultPassword);
	}
	
	protected void testHasPassword(boolean isDefaultPassword) throws Exception {
		
		// testee
		String encPassword = "ENCODED-PASSWORD";
		Credential cred = spy(new Credential());
		cred.setEncodedPassword(encPassword);
		
		// mock
		doReturn(isDefaultPassword).when(cred).isDefaultPassword(encPassword);
		
		// verify
		String msg = isDefaultPassword ?
				"hasPassword() should return false when the password is the default password." :
				"hasPassword() should return true when the password is not the default password.";
				
		assertEquals(msg, !isDefaultPassword, cred.hasPassword());
		verify(cred).isDefaultPassword(encPassword);
	}
	
	@Test
	public void testIsDefaultPassword() throws Exception {
		// testee
		Credential cred = new Credential();

		assertTrue(cred.isDefaultPassword(Utils.encodePassword("DEFAULT_PASSOWORD")));
		assertFalse(cred.isDefaultPassword(Utils.encodePassword("ANOTHER_PASSOWORD")));
	}
	
	@Test
	public void testIsCurrentPassword() {
		
		String inputPassword = "CURRENT-PASSWORD";
		
		// testee
		Credential cred = new Credential();
		
		// test(1)
		assertNull(cred.getEncodedPassword()); // supposing encoded password is not set.
		boolean result = cred.isCurrentPassword(null);
		assertTrue("isCurrentPassword() should return true if both the current password and the input are null.", result);

		// test(2)
		result = cred.isCurrentPassword(inputPassword);
		assertFalse("isCurrentPassword() should return false if the current password==null and the input!=null.", result);

		// test(3)
		cred.setEncodedPassword(Utils.encodePassword(inputPassword));
		result = cred.isCurrentPassword(null);
		assertFalse("isCurrentPassword() should return false if the current password!=null and the input==null.", result);
		
		// test(4)
		cred.setEncodedPassword(Utils.encodePassword(inputPassword));
		result = cred.isCurrentPassword(inputPassword);
		assertTrue("isCurrentPassword() should return true if the current password matches the input.", result);
	}
	
}
