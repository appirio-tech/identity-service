package com.appirio.tech.core.service.identity.util.ldap;

import java.lang.reflect.Field;

import org.apache.log4j.Logger;

import com.topcoder.security.ldap.LDAPClient;
import com.topcoder.security.ldap.LDAPClientException;
import com.topcoder.security.ldap.LDAPConstants;
import com.topcoder.util.net.ldap.sdkinterface.LDAPSDK;
import com.topcoder.util.net.ldap.sdkinterface.LDAPSDKConnection;
import com.topcoder.util.net.ldap.sdkinterface.LDAPSDKException;

public class LDAPService {

	Logger logger = Logger.getLogger(LDAPService.class);
	
	private boolean connectWithSSL = true;

	public LDAPService() {
	}
	
	/**
	 * CAUTION: Properties configured with this method are shared by all instances of LDAPService in the same VM.
	 * @param host
	 * @param port
	 * @param bindDN
	 * @param bindPassword
	 */
	public LDAPService(String host, Integer port, String bindDN, String bindPassword) {
		if(host!=null && host.length()>0)
			LDAPConstants.HOST = host;
		if(port!=null && port>0)
			LDAPConstants.PORT = port;
		if(bindDN!=null && bindDN.length()>0)
			LDAPConstants.BIND_DN = bindDN;
		if(bindPassword!=null && bindPassword.length()>0)
			LDAPConstants.BIND_PASSWORD = bindPassword;
	}
	
	public void setConnectWithSSL(boolean connectWithSSL) {
		this.connectWithSSL = connectWithSSL;
	}
	
	public void registerMember(Long userId, String handle, String password) {
		registerMember(userId, handle, password, MemberStatus.UNVERIFIED);
	}
	
	public void registerMember(Long userId, String handle, String password, MemberStatus status) {
		if(userId == null)
			throw new IllegalArgumentException("Invalid parameter: userId must be specified.");
		if(handle == null || handle.length()==0)
			throw new IllegalArgumentException("Invalid parameter: handle must be specified.");
		
		LDAPClient ldapClient = createLDAPClient();
		try {
			ldapClient.connect();
			MemberStatus s = status!=null ? status : MemberStatus.UNVERIFIED;
			ldapClient.addTopCoderMemberProfile(userId, handle, password, s.getValue());
			logger.info(String.format("[LDAP] User %s has been registered. (handle=\"%s\", status=\"%s\"", userId, handle, s.getValue()));
		} catch (LDAPClientException e) {
			logger.error(e.getMessage(), e);
			throw new RuntimeException("Failed to register member. (id:"+userId+", handle:"+handle+")", e);
		} finally {
			try {
				if(ldapClient.isConnected())
					ldapClient.disconnect();
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
		}
	}
	
	public void activateLDAPEntry(Long userId) {
		if(userId == null)
			throw new IllegalArgumentException("Invalid parameter: userId must be specified.");
		
		LDAPClient ldapClient = createLDAPClient();
		try {
			ldapClient.connect();
			ldapClient.activateTopCoderMemberProfile(userId);
			logger.info(String.format("[LDAP] User %s has been activated.", userId));
		} catch (LDAPClientException e) {
			logger.error(e.getMessage(), e);
			throw new RuntimeException("Failed to activate user. (id:"+userId+")", e);
		} finally {
			try {
				ldapClient.disconnect();
			} catch (LDAPClientException e) {
				logger.error("Failed to disconnect from LDAP server while activating user account. "
						+ "The process is not interrupted.");
			}
		}
	}
	
	public void changeHandleLDAPEntry(Long userId, String handle) {
		if(userId == null)
			throw new IllegalArgumentException("Invalid parameter: userId must be specified.");
		if(handle == null)
			throw new IllegalArgumentException("Invalid parameter: handle must be specified.");
		
		LDAPClient ldapClient = createLDAPClient();
		try {
			ldapClient.connect();
			ldapClient.setTopCoderMemberProfileHandle(userId, handle);
			logger.info(String.format("[LDAP] User %s's handle has been changed to '%s'.", userId, handle));
		} catch (LDAPClientException e) {
			logger.error(e.getMessage(), e);
			throw new RuntimeException("Failed to change handle. (id:"+userId+")", e);
		} finally {
			try {
				ldapClient.disconnect();
			} catch (LDAPClientException e) {
				logger.error("Failed to disconnect from LDAP server while activating user account. "
						+ "The process is not interrupted.");
			}
		}
	}

	public void changeStatusLDAPEntry(Long userId, String status) {
		if(userId == null)
			throw new IllegalArgumentException("Invalid parameter: userId must be specified.");
		if(status == null)
			throw new IllegalArgumentException("Invalid parameter: status must be specified.");
		MemberStatus memberStatus = MemberStatus.getByValue(status);
		if(memberStatus==null)
			throw new IllegalArgumentException("Invalid parameter: status is invalid. status: "+status);
		
		LDAPClient ldapClient = createLDAPClient();
		try {
			ldapClient.connect();
			ldapClient.setTopCoderMemberProfileStatus(userId, memberStatus.getValue());
			logger.info(String.format("[LDAP] User %s's status has been changed to '%s'.", userId, memberStatus.getValue()));
		} catch (LDAPClientException e) {
			logger.error(e.getMessage(), e);
			throw new RuntimeException("Failed to change status. (id:"+userId+")", e);
		} finally {
			try {
				ldapClient.disconnect();
			} catch (LDAPClientException e) {
				logger.error("Failed to disconnect from LDAP server while activating user account. "
						+ "The process is not interrupted.");
			}
		}
	}
	
	public void changePasswordLDAPEntry(Long userId, String password) {
		if(userId == null)
			throw new IllegalArgumentException("Invalid parameter: userId must be specified.");
		if(password == null)
			throw new IllegalArgumentException("Invalid parameter: password must be specified.");

		LDAPClient ldapClient = createLDAPClient();
		try {
			ldapClient.connect();
			ldapClient.changeTopCoderMemberProfilePassword(userId, password);
			logger.info(String.format("[LDAP] User %s's password has been changed.", userId));
		} catch (LDAPClientException e) {
			logger.error(e.getMessage(), e);
			throw new RuntimeException("Failed to change password. (id:"+userId+")", e);
		} finally {
			try {
				ldapClient.disconnect();
			} catch (LDAPClientException e) {
				logger.error("Failed to disconnect from LDAP server while activating user account. "
						+ "The process is not interrupted.");
			}
		}
	}
	
	public boolean authenticateLDAPEntry(String handle, String password) {
		if(handle == null)
			throw new IllegalArgumentException("Invalid parameter: handle must be specified.");
		if(password == null)
			throw new IllegalArgumentException("Invalid parameter: password must be specified.");
		
		try {
			LDAPClient.authenticateTopCoderMember(handle, password);
			logger.info(String.format("[LDAP] User %s has been authenticated.", handle));
			return true;
		} catch (LDAPClientException e) {
			if (e.isUserStatusNotActive()) {
				logger.info(String.format("[LDAP] User %s has not been activated.", handle));
				return true;
			} else if (e.isInvalidCredentialProvided() || e.isUnknownUserHandle()) {
				logger.info(String.format("[LDAP] Username and/or password are incorrect. handle:%s", handle));
				return false;
			} else {
				throw new RuntimeException("Could not authenticate user due to unexpected error", e);
			}
		}
	}
	
	protected LDAPClient createLDAPClient() {
		return new InnerLDAPClient(this.connectWithSSL);
	}
	
	public static class InnerLDAPClient extends LDAPClient {
		
		private boolean connectWithSSL = true;
		
		public InnerLDAPClient(){}
		
		public InnerLDAPClient(boolean connectWithSSL) {
			this.connectWithSSL = connectWithSSL;
		}
		
	    /**
	     * <p>Establishes authenticated connection to target <code>LDAP</code> server.</p>
	     *
	     * @throws LDAPClientException if an error occurs while establishing connection to target <code>LDAP</code> server
	     *         or authenticating to <code>LDAP</code> server.
	     */
		@Override
	    public void connect() throws LDAPClientException {
	        try {
	            LDAPSDK sdk = new LDAPSDK(LDAPConstants.CONNECTION_FACTORY);
	            LDAPSDKConnection ldapConnection = connectWithSSL ? sdk.createSSLConnection() : sdk.createConnection();
	            ldapConnection.connect(LDAPConstants.HOST, LDAPConstants.PORT);
	            ldapConnection.authenticate(LDAPConstants.BIND_DN, LDAPConstants.BIND_PASSWORD);
	            setLDAPConnection(ldapConnection);
	            
	        } catch (ClassNotFoundException e) {
	            //not visible: throw new LDAPClientException("LDAPClient failed to perform due to unexpected error", e, UNEXPECTED_ERROR);
	        	throw new RuntimeException("Failed to instantiate the LDAPSDKFactory instance", e);
	        } catch (LDAPSDKException e) {
	            //not visible: throw LDAPClientException.createUnexpectedErrorException(e);
	        	throw new RuntimeException("Failed to connect to LDAP server due to unexpected error : "+ e, e);
	        }
	    }
		
		protected void setLDAPConnection(LDAPSDKConnection ldapConnection) {
            try {
				Field ldapConnectionField = this.getClass().getSuperclass().getDeclaredField("ldapConnection");
				ldapConnectionField.setAccessible(true);
				ldapConnectionField.set(this, ldapConnection);
			} catch (Exception e) {
	        	throw new RuntimeException("Failed to set object on ldapConnection field. Error:"+e, e);
			}
		}
	}
	
	public static void main(String[] args) {
		Logger logger = Logger.getLogger(LDAPService.class);
		try {
			boolean connectWithSSL = false;
			InnerLDAPClient ldapClient = new InnerLDAPClient(connectWithSSL);
			ldapClient.connect();
			logger.info("**** ldapClient.isConnected(): " + ldapClient.isConnected());
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
}
