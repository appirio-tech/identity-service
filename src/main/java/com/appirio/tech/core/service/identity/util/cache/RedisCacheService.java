package com.appirio.tech.core.service.identity.util.cache;

import com.appirio.tech.core.service.identity.util.redis.RedisClient;

public class RedisCacheService implements CacheService {

	private RedisClient redis;
	
	public RedisCacheService(RedisClient redis) {
		this.redis = redis;
	}
	
	@Override
	public void put(String key, String value) {
		redis.put(key, value);
	}

	@Override
	public void put(String key, String value, int expirySeconds) {
		redis.put(key, value, expirySeconds);
	}

	@Override
	public String get(String key) {
		return redis.get(key);
	}

	@Override
	public String delete(String key) {
		String val = redis.get(key);
		redis.delete(key);
		return val;
	}
}
