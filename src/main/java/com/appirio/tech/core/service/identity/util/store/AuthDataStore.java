package com.appirio.tech.core.service.identity.util.store;

import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.log4j.Logger;

import com.appirio.tech.core.service.identity.representation.Authorization;
import com.appirio.tech.core.service.identity.util.Utils;

public class AuthDataStore {
	
	private ExecutorService service = Executors.newCachedThreadPool();

	private static final Logger logger = Logger.getLogger(AuthDataStore.class);

	public static final int DEFAULT_EXPIRY_SECONDS = 90 * 24 * 60 * 60;
	
	protected Map<String, Authorization> store = new ConcurrentHashMap<String, Authorization>();
	
	protected Map<String, Future<Authorization>> futureMap = new ConcurrentHashMap<String, Future<Authorization>>();

	protected int expirySeconds = DEFAULT_EXPIRY_SECONDS;
	
	public void put(Authorization auth) {
		if(auth==null)
			return;
		String key = key(auth);
		logger.debug("put ("+key+", "+auth+")");
		internalPut(key(auth), auth);
	}
	
	public Authorization get(String token, String target) {
		if(token==null || token.length()==0)
			return null;
		String key = key(token, target);
		Authorization auth = internalGet(key);
		logger.debug("get ("+key+") -> "+auth);
		return auth;
	}

	public void delete(String token, String target) {
		if(token==null || token.length()==0)
			return;
		String key = key(token, target);
		logger.debug("delete ("+key+")");		
		internalDelete(key);
	}

	protected String key(String token, String target) {
		String userId = getUserId(token);
		return "ap:identity:authorization:" + userId + ":" + (target!=null ? target : "");
	}

	protected String getUserId(String token) {
		try {
			Map<String, Object> claims = Utils.parseJWTClaims(token);
			return String.valueOf(claims.get("userId"));
		} catch (Exception e) {
			logger.error("Failed to extract user-id from JWT token. token:"+token, e);
			throw new RuntimeException("Failed to extract user-id from JWT token.", e);
		}
	}

	protected String key(Authorization auth) {
		return key(auth.getToken(), auth.getTarget());
	}

	protected void internalPut(String key, Authorization auth) {
		store.put(key, auth);
		
		Future<Authorization> future = futureMap.remove(key);
		if(future!=null && !future.isDone() && future.isCancelled()) {
			future.cancel(true);
		}
		
		final String k = key;
		future = service.submit(new Callable<Authorization>() {
			@Override public Authorization call() throws Exception {
				try {
					Thread.sleep(expirySeconds * 1000L);
				} catch (InterruptedException e) {}
				return store.remove(k);
			}
		});
		futureMap.put(key, future);
	}
	
	protected Authorization internalGet(String key) {
		return store.get(key);
	}

	protected void internalDelete(String key) {
		store.remove(key);
	}

	public int getExpirySeconds() {
		return expirySeconds;
	}

	public void setExpirySeconds(int expirySeconds) {
		this.expirySeconds = expirySeconds;
	}
}
