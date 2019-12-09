package com.appirio.tech.core.service.identity.util.redis;

import org.apache.log4j.Logger;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;


public class RedisClient {
	
	private static final Logger logger = Logger.getLogger(RedisClient.class);

	public static final int DEFAULT_POOL_SIZE = 10;
	
	public static final int DEFAULT_EXPIRY_SECONDS = 30 * 24 * 60 * 60; // 30d
	
	private int poolSize = DEFAULT_POOL_SIZE;
	
	private int expirySeconds = DEFAULT_EXPIRY_SECONDS;

	protected JedisPool pool;

	
	public RedisClient(String hostname, int port) {
		this(hostname, port, DEFAULT_POOL_SIZE);
	}
	
	public RedisClient(String hostname, int port, int poolSize) {
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

	public int getExpirySeconds() {
		return expirySeconds;
	}

	public void setExpirySeconds(int expirySeconds) {
		this.expirySeconds = expirySeconds;
	}

	public void put(String key, String value) {
		put(key, value, this.expirySeconds);
	}
	
	public void put(String key, String value, final int expirySeconds) {
		if(key==null)
			throw new IllegalArgumentException("key must be specified.");
		if(value==null)
			return;
		this.new Command<Void>() {
			@Override Void exec(Jedis jedis, Object... params) {
				String st = jedis.set((String)params[0], (String)params[1]);
				logger.debug(String.format("Set(%s,%s): %s", params[0], params[1], st));
				if(expirySeconds >= 0) {
					long res = jedis.expire((String)params[0], expirySeconds);
					logger.debug(String.format("Expire(%d, %s): %d", expirySeconds, params[0], res));
				}
				return null;
			}
		}.exec(key, value);
	}

	public String get(String key) {
		return this.new Command<String>() {
			@Override String exec(Jedis jedis, Object... params) {
				logger.debug(String.format("Get(%s)", params[0]));
				return jedis.get((String)params[0]);
			}
		}.exec(key);
	}
	
	public void delete(String key) {
		this.new Command<Void>() {
			@Override Void exec(Jedis jedis, Object... params) {
				Long res = jedis.del((String)params[0]);
				logger.debug(String.format("Del(%s): %d", params[0], res));
				return null;
			}
		}.exec(key);
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
