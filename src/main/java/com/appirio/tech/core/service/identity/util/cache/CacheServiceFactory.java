package com.appirio.tech.core.service.identity.util.cache;

import java.util.HashMap;
import java.util.Map;

import javax.validation.constraints.NotNull;

import org.apache.log4j.Logger;

import com.appirio.tech.core.service.identity.util.redis.RedisClient;

public class CacheServiceFactory {
	
	private static final Logger logger = Logger.getLogger(CacheServiceFactory.class);
	
	@NotNull
	private String type;
	
	private Map<String, Object> spec = new HashMap<String, Object>();

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public Map<String, Object> getSpec() {
		return spec;
	}

	public void setSpec(Map<String, Object> spec) {
		this.spec = spec;
	}
	
	public CacheService createCacheService() {
		if("memory".equals(type)) {
			logger.info("Creating In-Memory CacheService.");
			return new SimpleCacheService();
		}
		if("redis".equals(type)) {
			String host = this.spec.get("host").toString();
			if(host==null || host.length()==0)
				throw new IllegalArgumentException("host needs to be specified.");
			
			Integer port = 6379;
			try { port = Integer.valueOf(this.spec.get("port").toString()); } catch(Exception e){ logger.debug("port -> default"); }
			Integer poolSize = 0;
			try { poolSize = Integer.valueOf(this.spec.get("poolSize").toString()); } catch(Exception e){ logger.debug("pool-size -> default"); }

			logger.info(String.format("Creating Redis based CacheService with %s:%d. pool-size:%d", host, port, poolSize));
			return new RedisCacheService(new RedisClient(host, port, poolSize));
		}
		throw new IllegalArgumentException("Unknown CacheService type: "+type);
	}
}
