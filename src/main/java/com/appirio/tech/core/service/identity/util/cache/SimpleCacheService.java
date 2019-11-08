package com.appirio.tech.core.service.identity.util.cache;

import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.log4j.Logger;

public class SimpleCacheService implements CacheService {

	private static Logger logger = Logger.getLogger(SimpleCacheService.class);
	
	private Map<String, Object> cache = new ConcurrentHashMap<>();
	
	private Timer timer = new Timer();
	
	@Override
	public void put(String key, String value) {
		put(key, value, -1);
	}
	
	@Override
	public void put(String key, String value, int expirySeconds) {
		logger.debug("PUT ("+key+", "+value+")");
		cache.put(key, value);
		updateExpireTask(key, expirySeconds);
	}

	protected void updateExpireTask(String key, int expirySeconds) {
		String taskKey = ExpireTask.createKey(key);
		ExpireTask oldTask = (ExpireTask)cache.remove(taskKey);
		if(oldTask!=null) {
			logger.debug("DEF ("+key+") +"+expirySeconds);
			oldTask.cancel();
		}
		if(expirySeconds>0) {
			ExpireTask task = new ExpireTask(key, cache);
			timer.schedule(task, expirySeconds*1000L);
			cache.put(taskKey, task);
		}
	}
	
	@Override
	public String get(String key) {
		Object val = cache.get(key);
		logger.debug("GET ("+key+") -> "+val);
		return val==null ? null : (val instanceof String) ? (String)val : val.toString();
	}
	
	@Override
	public String delete(String key) {
		Object val = cache.remove(key);
		logger.debug("DEL ("+key+") -> "+val);
		return val==null ? null : (val instanceof String) ? (String)val : val.toString();
	}
	
	protected static class ExpireTask extends TimerTask {
		String key;
		Map<String, Object> cache;
		ExpireTask(String key, Map<String, Object> cache) {
			this.key = key;
			this.cache = cache;
		}
		@Override
		public void run() {
			logger.debug("EXP ("+key+")");
			this.cache.remove(key);
			this.cache.remove(createKey(key));
		}
		protected static String createKey(String key) {
			return "ExpireTask-"+key;
		}
	}
}
