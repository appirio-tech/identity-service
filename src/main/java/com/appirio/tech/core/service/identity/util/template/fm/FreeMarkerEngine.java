package com.appirio.tech.core.service.identity.util.template.fm;

import java.io.IOException;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import com.appirio.tech.core.service.identity.util.template.Template;
import com.appirio.tech.core.service.identity.util.template.TemplateEngine;
import com.appirio.tech.core.service.identity.util.template.TemplateStore;

import freemarker.template.Configuration;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;

public class FreeMarkerEngine extends TemplateEngine {

	private Map<String, String> env = new HashMap<String, String>();
	
	private Configuration cfg;
	
	public FreeMarkerEngine(TemplateStore templateStore) {
		this.configure(templateStore);
	}
	
	protected void configure(TemplateStore templateStore) {
		if(templateStore==null)
			throw new IllegalArgumentException("templateStore must be specified.");
		cfg = new Configuration();
        cfg.setDefaultEncoding("UTF-8");
        cfg.setTemplateExceptionHandler(TemplateExceptionHandler.IGNORE_HANDLER);
        cfg.setTemplateLoader(new StoreTemplateLoader(templateStore));
	}
	
	@Override
	public String mergeTemplate(Template template, Map<String, Object> context) {
		try {
			freemarker.template.Template tmp = cfg.getTemplate(template.getName());
			StringWriter writer = new StringWriter();
			Map<String, Object> ctx = new HashMap<String, Object>(context);
			ctx.putAll(env);
			tmp.process(ctx, writer);
			return writer.toString();
		} catch (IOException | TemplateException e) {
			throw new RuntimeException("Error in processing template "+template.getName(), e);
		}
	}
}
