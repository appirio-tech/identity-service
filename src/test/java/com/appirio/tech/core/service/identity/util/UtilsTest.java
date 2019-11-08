package com.appirio.tech.core.service.identity.util;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

public class UtilsTest {

	@Test
	public void testEncodeDecodePassword() throws Exception {
		String key = "password-hash-key";
		String password = "MY-PASSWORD";
		
		String encodedPassword = Utils.encodePassword(password, key);
		String decodedPassword = Utils.decodePassword(encodedPassword, key);
		
		assertEquals(password, decodedPassword);
	}
	
	@Test
	public void testEncodeDecodePassword_WithKeyInAppContext() throws Exception {
		String key = "password-hash-key";
		String password = "MY-PASSWORD";
		
		Map<String, Object> context = new HashMap<String, Object>();
		context.put("passwordHashKey", key);
		Utils.setApplicationContext(context);
		
		String encodedPassword = Utils.encodePassword(password);
		String decodedPassword = Utils.decodePassword(encodedPassword);
		
		assertEquals(password, decodedPassword);
	}
}
