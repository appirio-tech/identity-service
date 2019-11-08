package com.appirio.tech.core.service.identity.dao;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

import org.junit.Test;

public class EmailDAOTest {

	@Test
	public void testEmailExists() throws Exception {
		// testee
		EmailDAO testee = mock(EmailDAO.class);

		// test: for new email
		final String newEmail = "new@appirio.com";
		when(testee.emailExists(anyString())).thenCallRealMethod(); // testee
		when(testee.countEmail(newEmail)).thenReturn(0);

		boolean result = testee.emailExists(newEmail);
		assertFalse("emailExists(new-email) should return false", result);
		verify(testee).countEmail(newEmail);
		reset(testee);
		
		// test: for existing email
		final String existingEmail = "existing@appirio.com";
		when(testee.emailExists(anyString())).thenCallRealMethod(); // testee
		when(testee.countEmail(existingEmail)).thenReturn(1);
		
		result = testee.emailExists(existingEmail);
		assertTrue("emailExists(existing-email) should return true", result); 
		verify(testee).countEmail(existingEmail);
		reset(testee);

		// test: for illegal usage
		when(testee.emailExists(any())).thenCallRealMethod(); // testee
		try {
			result = testee.emailExists(null);
			fail("IllegalArgumentException should be thrown in the previous step.");
		} catch(IllegalArgumentException e) {
		}
	}

}
