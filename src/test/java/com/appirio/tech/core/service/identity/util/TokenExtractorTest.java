package com.appirio.tech.core.service.identity.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.junit.Test;

import com.appirio.tech.core.service.identity.dao.UserDAO;
import com.appirio.tech.core.service.identity.util.Utils.NumberTrimmingTokenExtractor;
import com.appirio.tech.core.service.identity.util.Utils.RegexTokenExtractor;

public class TokenExtractorTest {

	/* NumberTrimmingTokenExtractor */
	
	@Test
	public void testExtractTokens_HandleWithoutDigit() throws Exception {
		
		// testee
		NumberTrimmingTokenExtractor testee = new NumberTrimmingTokenExtractor(new HashSet<String>());
		
		// test
		String handle = "handle";
		Set<String> result = testee.extractTokens(handle);
		
		// verify
		assertNotNull(result);
		assertEquals(1, result.size());
		assertEquals(handle, result.iterator().next());
		
	}
	
	@Test
	public void testExtractTokens_HandleHasDigitesAtBothSide() throws Exception {
		
		// testee
		NumberTrimmingTokenExtractor testee = new NumberTrimmingTokenExtractor(new HashSet<String>());
		
		// test
		String handle = "12handle34";
		Set<String> result = testee.extractTokens(handle);
		
		// verify
		assertNotNull(result);
		containsAll(result, "12handle34", "12handle3", "12handle", "2handle34", "2handle3", "2handle", "handle34", "handle3", "handle");
	}
	
	@Test
	public void testExtractTokens_HandleHasDigitesAtLeftSide() throws Exception {
		
		// testee
		NumberTrimmingTokenExtractor testee = new NumberTrimmingTokenExtractor(new HashSet<String>());
		
		// test
		String handle = "12handle";
		Set<String> result = testee.extractTokens(handle);
		
		// verify
		assertNotNull(result);
		containsAll(result, "12handle", "2handle", "handle");
	}
	
	@Test
	public void testExtractTokens_HandleHasDigitesAtRightSide() throws Exception {
		
		// testee
		NumberTrimmingTokenExtractor testee = new NumberTrimmingTokenExtractor(new HashSet<String>());
		
		// test
		String handle = "handle34";
		Set<String> result = testee.extractTokens(handle);
		
		// verify
		assertNotNull(result);
		containsAll(result, "handle34", "handle3", "handle");
	}
	
	@Test
	public void testExtractTokens_IgnoreToken() throws Exception {
		
		// testee
		HashSet<String> ignoredTokens = new HashSet<String>(); 
		NumberTrimmingTokenExtractor testee = new NumberTrimmingTokenExtractor(ignoredTokens);
		
		// test
		String handle = "handle";
		ignoredTokens.add(handle);
		Set<String> result = testee.extractTokens(handle);
		
		// verify
		assertNotNull(result);
		assertEquals(0, result.size());
	}
	
	/* RegexTokenExtractor */
	
	@Test
	public void testExtractTokens_HandleDoesNotMatchAnyPattern() throws Exception {
		
		// testee
		RegexTokenExtractor testee = new RegexTokenExtractor(UserDAO.INVALID_HANDLE_PATTERNS, new HashSet<String>());
		
		// test
		String handle = "handle";
		Set<String> result = testee.extractTokens(handle);
		
		// verify
		assertNotNull(result);
		assertEquals(1, result.size());
		assertEquals(handle, result.iterator().next());
	}

	@Test
	public void testExtractTokens_HandleOfPluralForm() throws Exception {
		
		// testee
		RegexTokenExtractor testee = new RegexTokenExtractor(UserDAO.INVALID_HANDLE_PATTERNS, new HashSet<String>());
		
		// test
		String handle = "handles";
		Set<String> result = testee.extractTokens(handle);
		
		// verify
		assertNotNull(result);
		containsAll(result, "handles", "handle", "handl");
	}
	
	@Test
	public void testExtractTokens_HandleWithUnderscore() throws Exception {
		
		// testee
		RegexTokenExtractor testee = new RegexTokenExtractor(UserDAO.INVALID_HANDLE_PATTERNS, new HashSet<String>());
		
		// test
		String handle = "_handle_";
		Set<String> result = testee.extractTokens(handle);
		
		// verify
		assertNotNull(result);
		containsAll(result, "handle");
	}
	
	@Test
	public void testExtractTokens_RegexTokenExtractor_IgnoreToken() throws Exception {
		
		// testee
		String handle = "_handle_";
		Set<String> ignoredTokens = new HashSet<String>();
		RegexTokenExtractor testee = new RegexTokenExtractor(UserDAO.INVALID_HANDLE_PATTERNS, ignoredTokens);
		
		// test
		ignoredTokens.add("handle");
		Set<String> result = testee.extractTokens(handle);
		
		// verify
		assertNotNull(result);
		assertEquals(0, result.size());
	}


	
	@SafeVarargs
	static <T> void containsAll(Collection<T> collection, T... items) {
		assertEquals(items.length, collection.size());
		for(Iterator<T> tokens = Arrays.asList(items).iterator(); tokens.hasNext(); ) {
			T t = tokens.next();
			assertTrue(collection + " does not contain " + t, collection.contains(t));
		}
	}

}
