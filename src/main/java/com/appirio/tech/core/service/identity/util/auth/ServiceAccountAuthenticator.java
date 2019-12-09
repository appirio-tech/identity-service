package com.appirio.tech.core.service.identity.util.auth;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class ServiceAccountAuthenticator {

	private List<ServiceAccount> accounts = new LinkedList<ServiceAccount>();
	
	public List<ServiceAccount> getAccounts() {
		return accounts;
	}
	
	protected void setAccounts(List<ServiceAccount> accounts) {
		this.accounts = accounts;
	}

	public ServiceAccount authenticate(String clientId, String clientSecret) {
		if(accounts==null || accounts.size()==0)
			return null;
		for(Iterator<ServiceAccount> iter=accounts.iterator(); iter.hasNext(); ) {
			ServiceAccount acc = iter.next();
			if(clientId.equals(acc.getClientId()) && clientSecret.equals(acc.getClientSecret()))
				return acc;
		}
		return null;
	}
}
