package com.appirio.tech.core.service.identity.util.store;

import io.dropwizard.jackson.Jackson;

import java.io.IOException;

import org.apache.log4j.Logger;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import com.appirio.tech.core.service.identity.representation.Authorization;
import com.appirio.tech.core.service.identity.util.jackson.Views;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class RedisAuthDataStore extends AuthDataStore {
	
	private static final Logger logger = Logger.getLogger(RedisAuthDataStore.class);

	public static final int DEFAULT_POOL_SIZE = 10;
	
	private int poolSize = DEFAULT_POOL_SIZE;
	
	protected ObjectMapper objectMapper;

	protected JedisPool pool;

	
	public RedisAuthDataStore(String hostname, int port) {
		this(hostname, port, DEFAULT_POOL_SIZE);
	}
	
	public RedisAuthDataStore(String hostname, int port, int poolSize) {
		this.objectMapper = Jackson.newObjectMapper();
		if(poolSize>0)
			this.poolSize = poolSize;
		this.pool = createPool(hostname, port);
	}

	protected JedisPool createPool(String hostname, int port) {
		JedisPoolConfig config = new JedisPoolConfig();
		config.setMaxTotal(this.poolSize);
		return new JedisPool(config, hostname, port);
	}
	
	public int getPoolSize() {
		return poolSize;
	}

	protected void setPoolSize(int poolSize) {
		this.poolSize = poolSize;
	}

	@Override
	protected void internalPut(String key, Authorization auth) {
		if(key==null)
			throw new IllegalArgumentException("key must be specified.");
		if(auth==null)
			return;
		this.new Command<Void>() {
			@Override Void exec(Jedis jedis, Object... params) {
				int ttl = jedis.ttl((String)params[0]).intValue();
				String st = jedis.set((String)params[0], (String)params[1]);
				logger.debug(String.format("Set(%s,%s): %s", params[0], params[1], st));
				if(expirySeconds >= 0) {
					// if key exists in the cache and TTL is still positive, 
					// an expiration time to set is adjusted to keep the original expiration time.
					int exp = ttl > 0 ? ttl : expirySeconds;   
					long res = jedis.expire((String)params[0], exp);
					logger.debug(String.format("Expire(%d, %s): %d", exp, params[0], res));
				}
				return null;
			}
		}.exec(key, serialize(auth));
	}

	@Override
	protected Authorization internalGet(String key) {
		String json = this.new Command<String>() {
			@Override String exec(Jedis jedis, Object... params) {
				logger.debug(String.format("Get(%s)", params[0]));
				return jedis.get((String)params[0]);
			}
		}.exec(key);
		return json!=null ? deserialize(json) : null;
	}
	
	@Override
	protected void internalDelete(String key) {
		this.new Command<Void>() {
			@Override Void exec(Jedis jedis, Object... params) {
				Long res = jedis.del((String)params[0]);
				logger.debug(String.format("Del(%s): %d", params[0], res));
				return null;
			}
		}.exec(key);
	}
	
	protected String serialize(Authorization auth) {
		if(auth==null)
			throw new IllegalArgumentException("auth must be specified.");
		try {
			return this.objectMapper.writeValueAsString(auth);
		} catch (JsonProcessingException e) {
			throw new RuntimeException("Failed to jsonize Authorization object.", e); //TODO
		}
	}
	
	protected Authorization deserialize(String json) {
		if(json==null)
			throw new IllegalArgumentException("json must be specified.");
		try {
			return this.objectMapper.readValue(json, Authorization.class);
		} catch (IOException e) {
			throw new RuntimeException("Failed to build Authorization object from JSON text: "+json, e); //TODO
		}
	}
	
	protected abstract class Command<T> {
		abstract T exec(Jedis jedis, Object... params);
		protected T exec(Object... params) {
			try(Jedis jedis = getJedis()) {
				return this.exec(jedis, params);
			}
		}
		Jedis getJedis() {
			return pool.getResource();
		}
	}
}
