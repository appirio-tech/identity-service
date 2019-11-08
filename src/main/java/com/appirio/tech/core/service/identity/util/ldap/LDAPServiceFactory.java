package com.appirio.tech.core.service.identity.util.ldap;

public class LDAPServiceFactory {

	private String host;
	
	private Integer port;
	
	private String bindDN;
	
	private String bindPassword;
	
	private boolean useSSLConnection = true;
	
	public LDAPServiceFactory(){}
		
	public String getHost() {
		return host;
	}

	public void setHost(String host) {
		this.host = host;
	}

	public Integer getPort() {
		return port;
	}

	public void setPort(Integer port) {
		this.port = port;
	}

	public String getBindDN() {
		return bindDN;
	}

	public void setBindDN(String bindDN) {
		this.bindDN = bindDN;
	}

	public String getBindPassword() {
		return bindPassword;
	}
	
	public void setBindPassword(String bindPassword) {
		this.bindPassword = bindPassword;
	}

	public boolean isUseSSLConnection() {
		return useSSLConnection;
	}

	public void setUseSSLConnection(boolean useSSLConnection) {
		this.useSSLConnection = useSSLConnection;
	}

	public LDAPService createLDAPService() {
		LDAPService ldapService = new LDAPService(this.host, this.port, this.bindDN, this.bindPassword);
		ldapService.setConnectWithSSL(useSSLConnection);
		return ldapService;
	}
}
