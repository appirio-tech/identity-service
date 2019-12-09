package com.appirio.tech.core.service.identity.util.cache;

public interface CacheService {

	public abstract void put(String key, String value);

	public abstract void put(String key, String value, int expirySeconds);

	public abstract String get(String key);

	public abstract String delete(String key);

}