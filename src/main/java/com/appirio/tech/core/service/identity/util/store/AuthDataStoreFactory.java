package com.appirio.tech.core.service.identity.util.store;

import java.util.HashMap;
import java.util.Map;

import javax.validation.constraints.NotNull;

import org.apache.log4j.Logger;

public class AuthDataStoreFactory {

	private static final Logger logger = Logger.getLogger(AuthDataStoreFactory.class);
			
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
	
	public AuthDataStore createAuthDataStore() {
		if("memory".equals(type)) {
			logger.info("Creating In-Memory AuthDataStore.");
			return new AuthDataStore();
		}
		if("redis".equals(type)) {
			String host = this.spec.get("host").toString();
			if(host==null || host.length()==0)
				throw new IllegalArgumentException("host needs to be specified.");
			
			Integer port = 6379;
			try { port = Integer.valueOf(this.spec.get("port").toString()); } catch(Exception e){ logger.debug("port -> default"); }
			Integer poolSize = 0;
			try { poolSize = Integer.valueOf(this.spec.get("poolSize").toString()); } catch(Exception e){ logger.debug("pool-size -> default"); }
			Integer expirySeconds = null;
			try { expirySeconds = Integer.valueOf(this.spec.get("expirySeconds").toString()); } catch(Exception e){ logger.debug("expiry-seconds -> default"); }

			logger.info(String.format("Creating Redis based AuthDataStore with %s:%d. pool-size:%d, expiry-seconds:%d", host, port, poolSize, expirySeconds));
			RedisAuthDataStore store = new RedisAuthDataStore(host, port, poolSize);
			if(expirySeconds != null)
				store.setExpirySeconds(expirySeconds);
			return store;
		}
		throw new IllegalArgumentException("Unknown AuthDataStore type: "+type);
	}
}
