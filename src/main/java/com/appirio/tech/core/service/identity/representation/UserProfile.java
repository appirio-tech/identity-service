package com.appirio.tech.core.service.identity.representation;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonIgnore;


public class UserProfile {

	private String userId;
	
	private String name;
	
	private String email;
	
	private String providerType;
	
	private String provider;
	
	private boolean isEmailVerified = false;

	private Map<String, String> context;

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getProviderType() {
		return providerType;
	}

	@JsonIgnore
	public ProviderType getProviderTypeEnum() {
		return ProviderType.getByName(this.providerType);
	}

	@JsonIgnore
	public Integer getProviderTypeId() {
		ProviderType providerType = getProviderTypeEnum();
		return providerType!=null ? providerType.id : null;
	}
	
	@JsonProperty("providerId")
	public void setProviderTypeId(Integer providerId) {
		ProviderType providerType = ProviderType.getById(providerId);
		setProviderType(providerType!=null ? providerType.name : null);
	}
	
	public void setProviderType(String providerType) {
		this.providerType = providerType;
	}

	public String getProvider() {
		return provider;
	}

	public void setProvider(String provider) {
		this.provider = provider;
	}

	public boolean isEmailVerified() {
		return isEmailVerified;
	}

	public void setEmailVerified(boolean isEmailVerified) {
		this.isEmailVerified = isEmailVerified;
	}
	
	public Map<String, String> getContext() {
		return context;
	}

	public void setContext(Map<String, String> context) {
		this.context = context;
	}
	
	@JsonIgnore
	@Deprecated
	public String getLocalUserId() {
		if(userId==null)
			return null;
		String[] parts = userId.split("\\|");
		return parts[parts.length-1];
	}
	
	public boolean isSocial() {
		ProviderType providerType = getProviderTypeEnum();
		return providerType!=null ? providerType.isSocial : false;
	}
	
	public boolean isEnterprise() {
		ProviderType providerType = getProviderTypeEnum();
		return providerType!=null ? providerType.isEnterprise : false;
	}

	@SuppressWarnings("rawtypes")
	public void applyJWTClaims(Map<String, Object> claims) {
		if(claims==null || claims.size()==0)
			return;
		
		List identities = (List)claims.get("identities");
		if(identities!=null && identities.size()>0) {

			for(Iterator iter = identities.iterator(); iter.hasNext();) {
				Map identity = (Map)iter.next();
				if(!isAdoptable(identity))
					continue;
				setProviderType(String.valueOf(identity.get("provider")));
				setProvider(String.valueOf(identity.get("connection")));
				String userId = String.valueOf(identity.get("user_id"));
				String[] idItems = userId.split("\\|");
				setUserId(idItems[idItems.length-1]);
				break;
			}
		} else {

			String userId = null;
			if(claims.containsKey("user_id"))
				userId = String.valueOf(claims.get("user_id"));
			if(userId==null && claims.containsKey("sub"))
				userId = String.valueOf(claims.get("sub"));
			if(userId!=null) {
				String[] idItems = userId.split("\\|");
				setProviderType(idItems[0]);
				setUserId(idItems[idItems.length-1]);
			}
		}
		// for custom oauth connections, setting connection name to providerType.
		if(isCustomOAuthConnectionProviderType(getProviderType())) {
			setProviderType(getProvider());
		}
		setEmail(String.valueOf(claims.get("email")));
		
		ProviderType providerType = getProviderTypeEnum();
		if(providerType!=null) {
			setName(String.valueOf(claims.get(providerType.usernameField)));
		}
		setEmailVerified(claims.containsKey("email_verified") && (Boolean)claims.get("email_verified"));
	}

	/**
	 * true if provider is one of items in SocialProvider enum.
	 * when provider=="auth0", true if connection=="TC-User-Database"
	 * @param identity
	 * @return
	 */
	@SuppressWarnings("rawtypes")
	protected boolean isAdoptable(Map identity) {
		String provider = String.valueOf(identity.get("provider"));
		if(isCustomOAuthConnectionProviderType(provider))
			return true;
		
		ProviderType providerType = ProviderType.getByName(provider);
		if(providerType==null)
			return false;
		
		// known provider expect for "auth0"
		if(providerType!=ProviderType.AUTH0)
			return true;
		
		//true if connection=="TC-User-Database"
		String connection = String.valueOf(identity.get("connection"));
		return "TC-User-Database".equals(connection);
	}
	
	protected boolean isCustomOAuthConnectionProviderType(String providerType) {
		return "oauth1".equals(providerType) || "oauth2".equals(providerType);
	}
}
