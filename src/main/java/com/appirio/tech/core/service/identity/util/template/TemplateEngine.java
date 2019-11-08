package com.appirio.tech.core.service.identity.util.template;

import java.util.Map;

public abstract class TemplateEngine {

	public abstract String mergeTemplate(Template template, Map<String, Object> context);
}
