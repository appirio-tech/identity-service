package com.appirio.tech.core.service.identity.util.template;

import java.util.HashMap;
import java.util.Map;

public class Template {

	private String name;
	
	private String body;
	
	private long lastModified = -1L;
	
	protected Map<String, String> attributes = new HashMap<String, String>();

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getBody() {
		return body;
	}

	public void setBody(String body) {
		this.body = body;
	}
	
	public long getLastModified() {
		return lastModified;
	}

	public void setLastModified(long lastModified) {
		this.lastModified = lastModified;
	}

	public String getAttribute(String key) {
		return attributes.get(key);
	}
	
	public void setAttribute(String key, String attr) {
		attributes.put(key, attr);
	}
}
