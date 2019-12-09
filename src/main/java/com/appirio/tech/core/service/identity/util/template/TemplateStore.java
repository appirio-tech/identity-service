package com.appirio.tech.core.service.identity.util.template;

import java.util.List;
import java.util.Map;

public abstract class TemplateStore {

	public void configure(Map<String, String> env) {
	}
	
	public abstract Template getTemplate(String name);
	
	public abstract void updateTemplate(Template template);
	
	public abstract List<String> getTemplateNames();
}
