package com.appirio.tech.core.service.identity.util.template.fm;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;

import com.appirio.tech.core.service.identity.util.template.Template;
import com.appirio.tech.core.service.identity.util.template.TemplateStore;

import freemarker.cache.TemplateLoader;

public class StoreTemplateLoader implements TemplateLoader {

	private TemplateStore store;
	
	public StoreTemplateLoader(TemplateStore store) {
		this.store = store;
	}

	@Override
	public Object findTemplateSource(String name) throws IOException {
		return store.getTemplate(name);
	}

	@Override
	public long getLastModified(Object templateSource) {
		if(!(templateSource instanceof Template))
			throw new IllegalArgumentException("templateSource must be Template. templateSource:"+templateSource);
		
		Template tmp = (Template)templateSource;
		tmp = this.store.getTemplate(tmp.getName());
		return tmp!=null ? tmp.getLastModified() : -1L;
	}

	@Override
	public Reader getReader(Object templateSource, String encoding) throws IOException {
		if(!(templateSource instanceof Template))
			throw new IllegalArgumentException("templateSource must be Template. templateSource:"+templateSource);
		
		return new StringReader(((Template)templateSource).getBody());
	}

	@Override
	public void closeTemplateSource(Object templateSource) throws IOException {
	}

	protected TemplateStore getStore() {
		return store;
	}

	protected void setStore(TemplateStore store) {
		this.store = store;
	}
}
