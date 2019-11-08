package com.appirio.tech.core.service.identity.util.template;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.reflections.Reflections;
import org.reflections.scanners.ResourcesScanner;
import org.reflections.util.ClasspathHelper;
import org.reflections.util.ConfigurationBuilder;

public class ResourceTemplateStore extends TemplateStore {

	public static final Logger logger = Logger.getLogger(ResourceTemplateStore.class);
	
	public static final Pattern ATTR_LINE_PATTERN = Pattern.compile("^([\\S]+):(.+)$");

	protected final Map<String, Template> templates = new HashMap<String, Template>();
	
	public static final String ENV_KEY_RESOURCE_ROOT    = "resourcePath";
	public static final String ENV_KEY_RESOURCE_PATTERN = "resourcePattern";
	
	private String root = "template";
	
	private String resourcePattern = ".*\\.ftl";
	
	@Override
	public void configure(Map<String, String> env) {
		if(env!=null && env.size()>0) {
			if(env.containsKey(ENV_KEY_RESOURCE_ROOT))
				this.root = env.get(ENV_KEY_RESOURCE_ROOT);
			if(env.containsKey(ENV_KEY_RESOURCE_PATTERN))
				this.resourcePattern = env.get(ENV_KEY_RESOURCE_PATTERN);
		}
		for(Iterator<String> resources = scanTemplate(root, resourcePattern).iterator(); resources.hasNext(); ) {
			String resource = resources.next();
			Template tmp = loadTemplate(resource);
			templates.put(tmp.getName(), tmp);
		}
	}
	
	@Override
	public Template getTemplate(String name) {
		return templates.get(name);
	}
	
	@Override
	public void updateTemplate(Template template) {
		templates.put(template.getName(), template);
	}
	
	@Override
	public List<String> getTemplateNames() {
		return new ArrayList<String>(templates.keySet());
	}
	
	protected List<String> scanTemplate(String templatePackage, String filePattern) {
		Reflections reflections = 
				new Reflections(new ConfigurationBuilder()
					.addUrls(ClasspathHelper.forPackage(templatePackage))
					.setScanners(new ResourcesScanner()));
		
		Set<String> templates = reflections.getResources(Pattern.compile(filePattern));
		return new ArrayList<String>(templates);
	}
	
	protected Template loadTemplate(String resourcePath) {
		if(resourcePath==null)
			throw new IllegalArgumentException("resourcePath must be specified.");
		
		logger.debug("Loading tempalte from: "+resourcePath);
		
		Template template = new Template();
		template.setName(getNameFromPath(resourcePath));
		template.setAttribute("path", resourcePath);
		template.setLastModified(System.currentTimeMillis());

		StringWriter sw = new StringWriter();
		PrintWriter writer = new PrintWriter(sw);
		boolean inBody = false;
		try (Scanner scanner = new Scanner(getClass().getClassLoader().getResourceAsStream(resourcePath))) {
			while (scanner.hasNextLine()) {
				String line = scanner.nextLine();
				if(inBody) {
					writer.println(line);
					continue;
				}
				Matcher mat = ATTR_LINE_PATTERN.matcher(line);
				if(mat.matches()) {
					String key = mat.group(1);
					String attr = mat.group(2);
					logger.debug("Set attribute on template[" + template.getName() + "] (" + key + ", " + attr + ")");
					template.setAttribute(key, attr);
					continue;
				}
				inBody = true;
			}
		}
		template.setBody(sw.toString());
		return template;
	}

	// return "foo" for "template/xxx/foo.ftl"
	protected String getNameFromPath(String resourcePath) {
		if(resourcePath==null)
			throw new IllegalArgumentException("resourcePath must be specified.");
		return new File(resourcePath).getName().replaceFirst("\\.[^.]+$", "");
	}
	
	public static void main(String[] args) {
		ResourceTemplateStore store = new ResourceTemplateStore();
		store.configure(null);
		Template tmp = store.getTemplate("registration");
		System.out.println(tmp.getBody());
	}
}
