package com.appirio.tech.core.service.identity.representation;

public enum ProviderType {

	/*
	 * Social Conections
	 * id should be the same value in the social_login_provider table.
	 */
	/** Facebook */
	FACEBOOK(1, "facebook", true, false),
	/** Google */	
	GOOGLE(2, "google-oauth2", true, false),
	/** Twitter */
	TWITTER(3, "twitter", true, false, "screen_name"),
	/** Github */
	GITHUB(4, "github", true, false),
	/** SFDC */
	SFDC(5, "sfdc", true, false),
	
	/** Dribbble */
	DRIBBBLE(10, "dribbble", true, false, "username"),
	/** Behance */
	BEHANCE(11, "behance", true, false, "username"),
	/** Stack Overflow */ 
	STACKOVERFLOW(12, "stackoverflow", true, false, "username"),
	/** LinkedIn */ 
	LINKEDIN(13, "linkedin", true, false),
	/** Bitbucket */ 
	BITBUCKET(14, "bitbucket", true, false, "username"),

	/*
	 * Enterprise Connections
	 */
	/** LDAP */
	LDAP(101, "ad", false, true),
	/** SAML Provider */
	SAMLP(102, "samlp", false, true),
	/** ADFS */
	ADFS(103, "adfs", false, true),
	
	/*
	 * Auth0 Database Connections
	 */
	/** Auth0 */
	AUTH0(200, "auth0", false, false);
	
	public int id;
	
	public String name;
	
	public String usernameField;
	
	public boolean isSocial;
	
	public boolean isEnterprise;
	
	ProviderType(int id, String name, boolean isSocial, boolean isEnterprise, String usernameField) {
		this.id = id;
		this.name = name;
		this.isSocial = isSocial;
		this.isEnterprise = isEnterprise;
		this.usernameField = usernameField;
	}
	
	ProviderType(int id, String name, boolean isSocial, boolean isEnterprise) {
		this(id,name,isSocial,isEnterprise,"nickname");
	}
	
	public static ProviderType getById(int id) {
		ProviderType[] items = ProviderType.class.getEnumConstants();
		for(int i=0; i<items.length; i++) {
			if(items[i].id == id)
				return items[i];
		}
		return null;
	}
	
	public static ProviderType getByName(String name) {
		ProviderType[] items = ProviderType.class.getEnumConstants();
		for(int i=0; i<items.length; i++) {
			if(items[i].name.equals(name))
				return items[i];
		}
		return null;
	}
}
