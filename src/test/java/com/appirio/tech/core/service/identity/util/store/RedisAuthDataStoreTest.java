package com.appirio.tech.core.service.identity.util.store;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.junit.Test;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import com.appirio.tech.core.api.v3.util.jwt.JWTToken;
import com.appirio.tech.core.service.identity.representation.Authorization;

public class RedisAuthDataStoreTest {

	@Test
	public void testGet() throws Exception {
		
		// testee
		RedisAuthDataStore testee = new RedisAuthDataStore("host", 6379);
		
		// data
		Authorization auth = createTestDataAuthorization();
		String key = testee.key(auth.getToken(), auth.getTarget());
		String json = testee.serialize(auth);
		
		// mock: Jedis
		Jedis jedis = mock(Jedis.class);
		when(jedis.get(key)).thenReturn(json);
		
		// mock: Pool
		JedisPool pool = mock(JedisPool.class);
		when(pool.getResource()).thenReturn(jedis);
		testee.pool = pool;
		
		// test
		Authorization result = testee.get(auth.getToken(), auth.getTarget());
		
		// verify result
		assertNotNull(result);
		assertEquals(auth.getToken(), result.getToken());
		assertEquals(auth.getTarget(), result.getTarget());
		
		// verify mocks
		verify(pool).getResource();
		
		verify(jedis).get(key);
		verify(jedis).close(); // jedis should be closed.
	}
	
	
	@Test
	public void testGet_CloseJedisWhenError() throws Exception {
		// testee
		RedisAuthDataStore testee = new RedisAuthDataStore("host", 6379);
		
		// data
		Authorization auth = createTestDataAuthorization();
		String key = testee.key(auth.getToken(), auth.getTarget());
		
		// mock: Jedis
		Jedis jedis = mock(Jedis.class);
		Exception redisErr = new RuntimeException("Error in Redis");
		when(jedis.get(key)).thenThrow(redisErr);
		
		// mock: Pool
		JedisPool pool = mock(JedisPool.class);
		when(pool.getResource()).thenReturn(jedis);
		testee.pool = pool;
		
		// test
		try {
			testee.get(auth.getToken(), auth.getTarget());
			fail("Exception should be thrown in the previous step.");
		} catch (Exception e) {
			assertEquals(redisErr, e);
		}
		
		// verify mocks
		verify(pool).getResource();
		
		verify(jedis).get(key);
		verify(jedis).close(); // jedis should be closed.	
	}

	@Test
	public void testPut() throws Exception {
		testPut(3);
	}

	@Test
	public void testPut_ExpiryTimeIsNotSet() throws Exception {
		testPut(-1);
	}
	
	@Test
	public void testPut_FirstPut() throws Exception {
		testPut(-2);
	}

	protected void testPut(int ttl) throws Exception {
		
		// testee
		RedisAuthDataStore testee = new RedisAuthDataStore("host", 6379);
		int expirySeconds = 10;
		testee.setExpirySeconds(expirySeconds);
		
		// data
		Authorization auth = createTestDataAuthorization();
		String key = testee.key(auth.getToken(), auth.getTarget());
		String json = testee.serialize(auth);
		
		// mock: Jedis
		Jedis jedis = mock(Jedis.class);
		when(jedis.set(key, json)).thenReturn("status");
		when(jedis.ttl(key)).thenReturn((long)ttl);
		int nextExpirySeconds = ttl>0 ? ttl : expirySeconds;
		when(jedis.expire(key, nextExpirySeconds)).thenReturn(1L);
		
		// mock: Pool
		JedisPool pool = mock(JedisPool.class);
		when(pool.getResource()).thenReturn(jedis);
		testee.pool = pool;
		
		// test
		testee.put(auth);
		
		// verify mocks
		verify(pool).getResource();
		
		verify(jedis).ttl(key);
		verify(jedis).set(key, json);
		verify(jedis).expire(key, nextExpirySeconds);
		verify(jedis).close(); // jedis should be closed.
	}
	
	@Test
	public void testPut_CloseJedisWhenError() throws Exception {
		
		// testee
		RedisAuthDataStore testee = new RedisAuthDataStore("host", 6379);
		
		// data
		Authorization auth = createTestDataAuthorization();
		String key = testee.key(auth.getToken(), auth.getTarget());
		String json = testee.serialize(auth);
		
		// mock: Jedis
		Jedis jedis = mock(Jedis.class);
		Exception redisError = new RuntimeException("Redis Error");
		when(jedis.set(key, json)).thenThrow(redisError);
		
		// mock: Pool
		JedisPool pool = mock(JedisPool.class);
		when(pool.getResource()).thenReturn(jedis);
		testee.pool = pool;
		
		// test
		try {
			testee.put(auth);
			fail("Exception should be thrown in the previous step.");
		} catch (Exception e) {
			assertEquals(redisError, e);
		}
		
		// verify mocks
		verify(pool).getResource();
		
		verify(jedis).set(key, json);
		verify(jedis, never()).expire(anyString(), anyInt());
		verify(jedis).close(); // jedis should be closed.
	}
	
	@Test
	public void testDelete() throws Exception {
		
		// testee
		RedisAuthDataStore testee = new RedisAuthDataStore("host", 6379);
		
		// data
		Authorization auth = createTestDataAuthorization();
		String key = testee.key(auth.getToken(), auth.getTarget());
		
		// mock: Jedis
		Jedis jedis = mock(Jedis.class);
		when(jedis.del(key)).thenReturn(1L);
		
		// mock: Pool
		JedisPool pool = mock(JedisPool.class);
		when(pool.getResource()).thenReturn(jedis);
		testee.pool = pool;
		
		// test
		testee.delete(auth.getToken(), auth.getTarget());
		
		// verify mocks
		verify(pool).getResource();
		
		verify(jedis).del(key);
		verify(jedis).close(); // jedis should be closed.
	}
	
	
	@Test
	public void testDelete_CloseJedisWhenError() throws Exception {
		
		// testee
		RedisAuthDataStore testee = new RedisAuthDataStore("host", 6379);
		
		// data
		Authorization auth = createTestDataAuthorization();
		String key = testee.key(auth.getToken(), auth.getTarget());
		
		// mock: Jedis
		Jedis jedis = mock(Jedis.class);
		Exception redisError = new RuntimeException("Redis Error");
		when(jedis.del(key)).thenThrow(redisError);
		
		// mock: Pool
		JedisPool pool = mock(JedisPool.class);
		when(pool.getResource()).thenReturn(jedis);
		testee.pool = pool;
		
		// test
		try {
			testee.delete(auth.getToken(), auth.getTarget());
			fail("Exception should be thrown in the previous step.");
		} catch (Exception e) {
			assertEquals(redisError, e);
		}
		
		// verify mocks
		verify(pool).getResource();
		
		verify(jedis).del(key);
		verify(jedis).close(); // jedis should be closed.
	}
	
	
	@Test
	public void testMulti() throws Exception {
		
		// testee
		final RedisAuthDataStore testee = new RedisAuthDataStore("host", 6379);
		
		// data
		int size = 10;
		List<Authorization> authList = new ArrayList<Authorization>();
		for(int i=0; i<size; i++) {
			Authorization auth = createTestDataAuthorization();
			auth.setToken(auth.getToken()+"-"+i);
			authList.add(auth);
		}
		
		// mock: Jedis
		List<Jedis> jedisList = new ArrayList<Jedis>();
		for(Iterator<Authorization> iter=authList.iterator(); iter.hasNext();) {
			Authorization auth = iter.next();
			String key = testee.key(auth.getToken(), auth.getTarget());
			String json = testee.serialize(auth);
			Jedis jedis = mock(Jedis.class);
			when(jedis.set(key, json)).thenReturn("status");
			when(jedis.expire(key, testee.getExpirySeconds())).thenReturn(1L);
			when(jedis.get(key)).thenReturn(json);
			when(jedis.del(key)).thenReturn(1L);
			jedisList.add(jedis);
		}
		
		// mock: Pool
		JedisPool pool = mock(JedisPool.class);
		Jedis[] jedisArray = new Jedis[jedisList.size()-1];
		for(int i=1; i<jedisList.size(); i++) {
			jedisArray[i-1] = jedisList.get(i);
		}
		when(pool.getResource()).thenReturn(jedisList.get(0), jedisArray);
		testee.pool = pool;
		
		// test
		Thread[] procs = new Thread[authList.size()];
		for(int i=0; i<authList.size(); i++) {
			final Authorization auth = authList.get(i);
			procs[i] = new Thread(
					new Runnable() {
						@Override public void run() {
							testee.put(auth);
						}});
			procs[i].start();
		}
		for(int i=0; i<procs.length; i++) {
			procs[i].join();
		}
		
		// verify mock: pool
		verify(pool, times(size)).getResource();
		// verify mock: jedis
		for(Iterator<Jedis> iter=jedisList.iterator(); iter.hasNext();) {
			Jedis jedis = iter.next();
			verify(jedis).set(anyString(), anyString());
			verify(jedis).expire(anyString(), anyInt());
			verify(jedis).close(); // jedis should be closed.
		}
	}

	protected Authorization createTestDataAuthorization() {
		JWTToken token = new JWTToken();
		token.setUserId("USER-ID-DUMMY");
		token.setIssuer("JWT-ISSUER-DUMMY");
		
		Authorization auth = new Authorization();
		auth.setToken(token.generateToken("SECRET-DUMMY"));
		auth.setTarget("1");
		return auth;
	}
}
