package com.appirio.tech.core.service.identity.util;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;

public class HttpUtil {
	
	private static final Logger logger = Logger.getLogger(HttpUtil.class);
	
	public static final int DEFAULT_REQUEST_RETRY_COUNT = 2;
	public static final int DEFAULT_RETRY_INTERVAL_SECONDS = 1;

	public static String getAuthorizationParam(String type, HttpServletRequest request) {
		if(request==null)
			throw new IllegalArgumentException("request must be specified.");
		
		String authHeader = request.getHeader("Authorization");
		if(authHeader==null || authHeader.length()==0)
			return null;
		if(type==null || type.length()==0)
			return authHeader;
		if(!authHeader.trim().startsWith(type))
			return null;
		
		return authHeader.substring(type.length()).trim();
	}
	
	public static class Request {
		private String endpoint;
		private String method;
		private int retryCount = DEFAULT_REQUEST_RETRY_COUNT;
		private int retryIntervalSeconds = DEFAULT_RETRY_INTERVAL_SECONDS;
		private Map<String, String> headers = new HashMap<String, String>();
		private Map<String, String> params = new HashMap<String, String>();
		private String jsonBody;
		
		public Request() {}
		
		public Request(String endpoint, String method) {
			this.endpoint = endpoint;
			this.method = method;
		}
		public String getEndpoint() {
			return endpoint;
		}
		public void setEndpoint(String endpoint) {
			this.endpoint = endpoint;
		}
		public String getMethod() {
			return method;
		}
		public void setMethod(String method) {
			this.method = method;
		}
		public int getRetryCount() {
			return retryCount;
		}
		public void setRetryCount(int retryCount) {
			this.retryCount = retryCount;
		}
		public int getRetryIntervalSeconds() {
			return retryIntervalSeconds;
		}
		public void setRetryIntervalSeconds(int retryIntervalSeconds) {
			this.retryIntervalSeconds = retryIntervalSeconds;
		}

		public Request endpoint(String endpoint) {
			setEndpoint(endpoint);
			return this;
		}
		public Request method(String method) {
			setMethod(method);
			return this;
		}
		public Request param(String key, String value) {
			this.params.put(key, value);
			return this;
		}
		public Request header(String key, String value) {
			this.headers.put(key, value);
			return this;
		}
		public Request json(String json) {
			this.jsonBody = json;
			return this;
		}
		public Request retry(int count) {
			setRetryCount(count);
			return this;
		}

		public Map<String, String> getHeaders() {
			return this.headers;
		}
		public String getHeader(String key) {
			return this.headers!=null ? this.headers.get(key) : null;
		}
		public Map<String, String> getParams() {
			return params;
		}
		public String getParam(String key) {
			return this.params!=null ? this.params.get(key) : null;
		}
		public String getQuery() {
			if(this.params==null || this.params.size()==0)
				return "";
			StringBuilder sb = new StringBuilder();
			for(Iterator<String> keys= this.params.keySet().iterator(); keys.hasNext();) {
				String key = keys.next();
				try {
					String val = this.params.get(key);
					sb.append(URLEncoder.encode(key, "UTF-8"))
						.append("=")
						.append(URLEncoder.encode(val==null ? "" : val, "UTF-8"))
						.append("&");
				} catch (UnsupportedEncodingException e) {}
			}
			return sb.toString().replaceFirst("&$", "");
		}
		public Response execute() throws Exception {
			Object result = null;
			int trial = this.retryCount>0 ? this.retryCount+1 : 1;
			for(int cnt=0; cnt<trial; cnt++) {
				try {
					Response resp = internalExecute();
					if(!resp.isServerError()) {
						return resp;
					}
					logger.error(String.format("Server error: %d %s", resp.getStatusCode(), resp.getMessage()));
					result = resp;
				} catch(Exception e) {
					logger.error("Error occurred in HTTP access. "+e, e);
					result = e;
				}
				if(cnt<(trial-1) && this.retryIntervalSeconds > 0) {
					try { Thread.sleep(1000L*this.retryIntervalSeconds); } catch(Exception e){}
					logger.debug(String.format("Retry(%d): %s %s", cnt+1, this.getMethod(), this.getEndpoint()));
				}
			}
			if(result!=null && result instanceof Response)
				return (Response) result;
			
			throw result!=null && result instanceof Exception ?
					(Exception)result : new Exception("HTTP request failed.");
		}
		
		protected boolean isWritable() {
			String method = getMethod();
			return ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method));
		}
		
		protected Response internalExecute() throws Exception {
			logger.debug(String.format("Request: %s %s", this.getMethod(), this.getEndpoint()));
			logger.debug(String.format("Query: %s", this.getQuery()));
			logger.debug(String.format("Body: %s", this.jsonBody));
			HttpURLConnection conn = openHttpConnection();
			try {
				if(isWritable()) {
					conn.setDoOutput(true);
				}
				conn.setUseCaches(false);
				conn.setRequestMethod(this.getMethod());
				Map<String, String> headers = this.getHeaders();
				if(headers!=null && headers.size()>0) {
					for(Iterator<String> keys = headers.keySet().iterator(); keys.hasNext(); ) {
						String key = keys.next();
						String header = headers.get(key);
						logger.debug("Header "+key+" : "+header);
						conn.setRequestProperty(key, headers.get(key));
					}
				}
				if(isWritable()) {
					String data = this.getQuery();
					if(data != null && data.length()>0) {
						conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
					}
					else if (this.jsonBody != null && this.jsonBody.length()>0) {
						conn.setRequestProperty("Content-Type", "application/json");
						data = this.jsonBody;
					}
					try(PrintWriter writer = new PrintWriter(conn.getOutputStream())) {
						writer.print(data);
					}
				}
				Response response = new Response(conn.getResponseCode(), conn.getResponseMessage());
				Map<String, List<String>> headerFields = conn.getHeaderFields();
				for(Iterator<String> keys = headerFields.keySet().iterator(); keys.hasNext();) {
					String key = keys.next();
					response.setHeader(key, concat(headerFields.get(key)));
				}
				logger.debug(String.format("Reponse: %d %s", response.getStatusCode(), response.getMessage()));
				
				try(InputStream in = conn.getInputStream()) {
					StringBuilder sb = new StringBuilder();
					BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF8"));
					String str = null;
					while ((str = reader.readLine()) != null)
						sb.append(str);
					response.setText(sb.toString());
				} catch(Exception e) {
					StringWriter sw = new StringWriter();
					e.printStackTrace(new PrintWriter(sw));
					response.setText(sw.toString());
				}
				logger.debug("Contents:" + response.getText());
				return response;
			} finally {
				if(conn!=null) try { conn.disconnect(); } catch(Exception e) { logger.warn(e); }
			}
		}

		protected HttpURLConnection openHttpConnection() throws Exception {
			return (HttpURLConnection) new URL(this.getEndpoint()).openConnection();
		}
		
		protected String concat(List<String> values) {
			if(values==null || values.size()==0)
				return "";
			if(values.size()==1)
				return values.get(0);
			
			StringBuilder sb = new StringBuilder();
			for(Iterator<String> iter = values.iterator(); iter.hasNext();)
				sb.append(iter.next()).append(";");
			return sb.toString().replaceFirst(";$", "");
		}
	}
	
	public static class Response {
		private Integer statusCode;
		private String message;
		private Map<String, String> headers = new HashMap<String, String>();
		private String contents;
		
		public Response() {}
			
		public Response(Integer statusCode, String message) {
			this.statusCode = statusCode;
			this.message = message;
		}
		
		public Integer getStatusCode() {
			return statusCode;
		}
		protected void setStatusCode(Integer statusCode) {
			this.statusCode = statusCode;
		}
		public String getMessage() {
			return this.message;
		}
		protected void setMessage(String message) {
			this.message = message;
		}
		public Map<String, String> getHeaders() {
			return this.headers;
		}
		public String getHeader(String key) {
			return this.headers!=null ? this.headers.get(key) : null;
		}
		protected void setHeader(String key, String value) {
			this.headers.put(key, value);
		}
		public String getText() {
			return this.contents;
		}
		protected void setText(String text) {
			this.contents = text;
		}
		public boolean isServerError() {
			if(this.statusCode==null)
				return false;
			return this.statusCode % 500 < 100;
		}
	}
}
