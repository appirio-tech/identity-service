package com.appirio.tech.core.service.identity.resource;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;
import static com.appirio.tech.core.service.identity.resource.AuthorizationResource.MAX_COOKIE_EXPIRY_SECONDS;

import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import com.appirio.tech.core.service.identity.util.Utils;
import org.junit.Test;
import org.mockito.Mockito;

import com.appirio.tech.core.api.v3.ApiVersion;
import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.request.PostPutRequest;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.api.v3.util.jwt.JWTToken;
import com.appirio.tech.core.service.identity.dao.RoleDAO;
import com.appirio.tech.core.service.identity.dao.SocialUserDAO;
import com.appirio.tech.core.service.identity.dao.UserDAO;
import com.appirio.tech.core.service.identity.representation.Authorization;
import com.appirio.tech.core.service.identity.representation.ProviderType;
import com.appirio.tech.core.service.identity.representation.Role;
import com.appirio.tech.core.service.identity.representation.User;
import com.appirio.tech.core.service.identity.representation.UserProfile;
import com.appirio.tech.core.service.identity.util.auth.Auth0Client;
import com.appirio.tech.core.service.identity.util.auth.Auth0Credential;
import com.appirio.tech.core.service.identity.util.auth.ServiceAccount;
import com.appirio.tech.core.service.identity.util.auth.ServiceAccountAuthenticator;
import com.appirio.tech.core.service.identity.util.cache.CacheService;
import com.appirio.tech.core.service.identity.util.store.AuthDataStore;
import com.appirio.tech.core.service.identity.util.zendesk.ZendeskAuthPlugin;

/**
 * AuthorizationResourceTest is used to test the authorization resources 
 * 
 * <p>
 * Changes in the verstion 1.1 (Topcoder - Provide Way to Refresh Auth0 Tokens In authorizations API v1.0)
 * - udpate the dependency of java jwt version 3.2.0
 * - add more tests for the new added methods
 * </p>
 * 
 * @author TCCoder
 * @version 1.1
 *
 */
public class AuthorizationResourceTest {

	static final String JWT_SECRET = "JWT-SECRET";
	
	static {
		System.setProperty("TC_JWT_KEY", JWT_SECRET);
	}
	
	public static class TestTokenCreator {
		public static String getAuth0Code() {
			return "AUTH0-CODE-DUMMY";
		}
		public static String getPrimaryAuth0JWT() {
			JWTToken jwt = new JWTToken();
			jwt.setIssuer(jwt.createIssuerFor("AUTH0_DOMAIN"));
			return jwt.generateToken(getSecret());
		}
		public static String getSecondaryAuth0JWT() {
			JWTToken jwt = new JWTToken();
			jwt.setIssuer(jwt.createIssuerFor("AUTH0_DOMAIN"));
			return jwt.generateToken(getSecret());
		}
		public static String getExternalToken() {
			return "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSldULU5BTUUiLCJleHRlcm"
			        + "5hbF9pZCI6IkpXVC1VU0VSLUlEIiwiaWF0IjoxNTEyNjU0MjI1LCJlbWFpbCI6IkpXVC1FTUFJ"
			        + "TCIsImp0aSI6IjI0NjYyNDExLTVlMTktNDdjYS1hMzcyLWVjODk3YWI2ZjMyNCJ9"
			        + ".IOAbV2XlkD2igcg-4KTtAu2hwZD_vFPcie_EI7HNYKU";
		}
		public static String getRefreshToken() {
			return "AUTH0-REFRESH-TOKEN-DUMMY";
		}
		public static String getDomain() {
			return "DOMAIN-DUMMY";
		}
		public static String getSecret() {
			return JWT_SECRET;
		}
		public static String getPrimaryJWTToken() {
			JWTToken jwt = new JWTToken();
			jwt.setIssuer(jwt.createIssuerFor(getDomain()));
			return jwt.generateToken(getSecret());
		}
		public static String getSecondaryJWTToken() {
			JWTToken jwt = new JWTToken();
			jwt.setIssuer(jwt.createIssuerFor(getDomain()));
			return jwt.generateToken(getSecret());
		}
	}
	
	@Test
	public void testCreateObject() throws Exception {
		
		// data
		Authorization auth = new Authorization();
		auth.setExternalToken(TestTokenCreator.getExternalToken());
		auth.setRefreshToken(TestTokenCreator.getRefreshToken());
		
		// mock: request/response
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);

		// mock: PostPutRequest
		@SuppressWarnings("unchecked")
		PostPutRequest<Authorization> postRequest = (PostPutRequest<Authorization>)mock(PostPutRequest.class);
		when(postRequest.getParam()).thenReturn(auth);
		
		// mock: Auth0Client
		Auth0Client auth0 = mock(Auth0Client.class);
		
		// mock: ZendeskAuthPlugin
		final String zendeskJwt = "DUMMY-ZD-TOKEN";
		ZendeskAuthPlugin zendeskAuthPlugin = spy(new ZendeskAuthPlugin(){
			@Override public Authorization process(Authorization auth) {
				auth.setZendeskJwt(zendeskJwt);
				return auth;
			}});

		// target
		String newToken = TestTokenCreator.getPrimaryJWTToken();
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), new AuthDataStore(), auth0, null, null, null, null));
		testee.setZendeskAuthPlugin(zendeskAuthPlugin);
		
		doReturn(newToken).when(testee).createJWTToken(auth.getExternalToken());
		doNothing().when(testee).updateLastLoginDate(auth);
		doNothing().when(testee).processTCCookies(auth, request, response, false);

		// test
		ApiResponse result = testee.createObject(postRequest, request, response);
		
		// verify result
		// API version
		assertEquals(ApiVersion.v3, result.getVersion());
		// result
		assertNotNull(result.getResult());
		assertEquals(HttpURLConnection.HTTP_OK, (int)result.getResult().getStatus());
		assertTrue("ApiResponse.Result should be success.", result.getResult().getSuccess());
		
		// authorization
		Authorization authInResponse = (Authorization)result.getResult().getContent();
		assertNotNull(authInResponse);
		assertEquals(newToken, authInResponse.getToken());
		assertEquals(auth.getExternalToken(), authInResponse.getExternalToken());
		assertEquals(auth.getRefreshToken(), authInResponse.getRefreshToken());
		assertEquals("1", auth.getTarget());
		assertEquals(zendeskJwt, authInResponse.getZendeskJwt());
		
		// created auth should be stored in data store
		Authorization authStored = testee.getAuthDataStore().get(authInResponse.getToken(), authInResponse.getTarget());
		assertNotNull(authStored);
		assertEquals(authInResponse.getId(), authStored.getId());
		
		// verify mock
		verify(request, never()).getHeader("Authorization");
		verify(postRequest).getParam();
		verify(zendeskAuthPlugin).process(auth);
		verify(testee, atLeastOnce()).createJWTToken(auth.getExternalToken());
		verify(testee).updateLastLoginDate(auth);
		verify(testee).processTCCookies(authInResponse, request, response, false);
	}
	
	@Test
    public void testCreateObject_get_refresh_token_for_RS256() throws Exception {
	    // the old token
        String rs256Token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsI"
                + "mtpZCI6Ik9UbENOMFk0UVRWQlJERTJSRGt3TURneU56QkRSVFZFTj"
                + "BGQ09VVTRSalF6T0RWQ016QkRSUSJ9.eyJpc3MiOiJodHRwczovL3RvcGNvZGVyLW5ld"
                + "2F1dGguYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDQwMTUzOTU2IiwiYXVkIjpbImh0dHBz"
                + "Oi8vYXBpLnRvcGNvZGVyLWRldi5jb20vdjMiLCJodHRwczovL3RvcGNvZGVyLW5ld2F1dG"
                + "guYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTUxMjY0NjM5MiwiZXhwIjoxNTEyNzMy"
                + "NzkyLCJhenAiOiJHNzZhcjJTSTR0WHowakF5RWJWR003akZ4aGVSbmtxYyIsInNjb3BlIj"
                + "oib3BlbmlkIHByb2ZpbGUgb2ZmbGluZV9hY2Nlc3MifQ.QI_-Bfi2NUAzhWxibcIFBlRRc"
                + "Ch1IJPrdywrFlMeTEnzAZzsvL6ujBConoDC7QUoz1z7Upplp_RxdB4gXii_g5DnZwcUhYC"
                + "MGl7auP3sTdiglu_dQSgopBrRfKcZDA3lMkWUvru-C8Qwqnkz4zMoMQQHXGY7wwNx6R0Ai"
                + "vJk9zaf0BTgVjr9327z8DsEmoDPFQu2grrrxnBaY4PPcdXesoVG5RIjEXca9kxGNMmiahN"
                + "rLcIGi9R5zJCg39u_cMMm9WyRZ7D9Cb3GmVC2GiZo2VtT_Unl-K9mqADk3AZIKP_Vefuw1"
                + "SX5_2kd3bFJjys7KL-1gdy3vIY_Oq5cL5lvQA";
        
        // the new token retrieved by refresh token
        String newRs256 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik9UbENOMFk0UVRWQlJ"
                + "ERTJSRGt3TURneU56QkRSVFZFTjBGQ09VVTRSalF6T0RWQ016QkRSUSJ9.eyJpc3MiOiJod"
                + "HRwczovL3RvcGNvZGVyLW5ld2F1dGguYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDQwMTUz"
                + "OTU2IiwiYXVkIjpbImh0dHBzOi8vYXBpLnRvcGNvZGVyLWRldi5jb20vdjMiLCJodHRwczo"
                + "vL3RvcGNvZGVyLW5ld2F1dGguYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTUxMjY1Nz"
                + "gxOCwiZXhwIjoxNTEyNzQ0MjE4LCJhenAiOiJHNzZhcjJTSTR0WHowakF5RWJWR003akZ4a"
                + "GVSbmtxYyIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgb2ZmbGluZV9hY2Nlc3MifQ.YqOUK"
                + "8Xruuk4Cb0eAtO0uainD6mzjDmScncthDlmZFMXLH4yg80tOJ8k-aJfRajhcnT4WRcsf0oj"
                + "M3QfyE1Ik5C7VEH4ez_YAya67mQg4hf_WP6f1YXeha2dVuYq4NW9h2yVSnOP29H92hCtxue"
                + "K6_mhmRnukOtDK_nlMwJFmRmPLaIyW3hzXSWOinsE3gErO5VRrOw9yrN1mmxF9jgf6ZPDJ5"
                + "GU4rwyeu63E5Yp8KrZXMFzQhruiBCwMwxxk2maiEtsaQgP6C61-PAZeL3eMTzIQgndhtuzB"
                + "JFcXgB-ANdOwXtrYS7irzRkTB-D47iySje-JnFtfkv5Y4k609XEew";
        // data
        Authorization auth = new Authorization();
        auth.setExternalToken(rs256Token);
        auth.setRefreshToken(TestTokenCreator.getRefreshToken());
        
        // mock: request/response
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        // mock: PostPutRequest
        @SuppressWarnings("unchecked")
        PostPutRequest<Authorization> postRequest = (PostPutRequest<Authorization>)mock(PostPutRequest.class);
        when(postRequest.getParam()).thenReturn(auth);
        
        // mock: Auth0Client
        Auth0Client auth0 = mock(Auth0Client.class);
        Auth0Client auth0New = mock(Auth0Client.class);
        
        // mock: ZendeskAuthPlugin
        final String zendeskJwt = "DUMMY-ZD-TOKEN";
        ZendeskAuthPlugin zendeskAuthPlugin = spy(new ZendeskAuthPlugin(){
            @Override public Authorization process(Authorization auth) {
                auth.setZendeskJwt(zendeskJwt);
                return auth;
            }});

        // target
        CacheService cacheService = mock(CacheService.class);
        AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), new AuthDataStore(), auth0, auth0New, null, null, null, cacheService));
        testee.setZendeskAuthPlugin(zendeskAuthPlugin);
        
        doReturn(TestTokenCreator.getRefreshToken()).when(cacheService).get(rs256Token);
        
        Auth0Credential cred = new Auth0Credential();
        cred.setAccessToken(newRs256);
        cred.setIdToken("id");
        doReturn(cred).when(auth0New).refreshToken(TestTokenCreator.getRefreshToken());
        
        
        //doReturn(newToken).when(testee).createJWTToken(auth.getExternalToken());
        doNothing().when(testee).updateLastLoginDate(auth);
        doNothing().when(testee).processTCCookies(auth, request, response, true);

        // test
        ApiResponse result = testee.createObject(postRequest, request, response);
        
        // verify result
        // API version
        assertEquals(ApiVersion.v3, result.getVersion());
        // result
        assertNotNull(result.getResult());
        assertEquals(HttpURLConnection.HTTP_OK, (int)result.getResult().getStatus());
        assertTrue("ApiResponse.Result should be success.", result.getResult().getSuccess());
        
        // authorization
        Authorization authInResponse = (Authorization)result.getResult().getContent();
        assertNotNull(authInResponse);
        assertEquals(newRs256, authInResponse.getToken());
        assertEquals(auth.getExternalToken(), authInResponse.getExternalToken());
        assertEquals(auth.getRefreshToken(), authInResponse.getRefreshToken());
        assertEquals("1", auth.getTarget());
        assertEquals(zendeskJwt, authInResponse.getZendeskJwt());
        
        // created auth should be stored in data store
        Authorization authStored = testee.getAuthDataStore().get(authInResponse.getToken(), authInResponse.getTarget());
        assertNotNull(authStored);
        assertEquals(authInResponse.getId(), authStored.getId());
        
        // verify mock
        verify(request, never()).getHeader("Authorization");
        verify(postRequest).getParam();
        verify(zendeskAuthPlugin).process(auth);
        verify(testee, org.mockito.Mockito.never()).createJWTToken(auth.getExternalToken());
        verify(testee).updateLastLoginDate(auth);
        verify(testee).processTCCookies(authInResponse, request, response, true);
    }
	
	@Test
	public void testCreateObject_400WhenPayloadIsMissing() throws Exception {
		// mock: PostPutRequest
		@SuppressWarnings("unchecked")
		PostPutRequest<Authorization> postRequest = (PostPutRequest<Authorization>)mock(PostPutRequest.class);
		when(postRequest.getParam()).thenReturn(null); // no payload
		// mock
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);

		// target
		AuthorizationResource testee = new AuthorizationResource(TestTokenCreator.getDomain(), new AuthDataStore(), null, null, null, null, null);
		
		try {
			// test
			testee.createObject(postRequest, request, response);
			fail("APIRuntimeException should be thrown in the previous step.");
		} catch (APIRuntimeException e) {
			assertEquals(HttpURLConnection.HTTP_BAD_REQUEST, e.getHttpStatus());
		}
		
		// verify
		verify(postRequest).getParam();
	}
	
	@Test
	public void testCreateObject_400WhenExternalTokenIsMissing() throws Exception {
		// data
		Authorization auth = new Authorization(); // no external token
		
		// mock: PostPutRequest
		@SuppressWarnings("unchecked")
		PostPutRequest<Authorization> postRequest = (PostPutRequest<Authorization>)mock(PostPutRequest.class);
		when(postRequest.getParam()).thenReturn(auth);
		// mock
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);

		// target
		AuthorizationResource testee = new AuthorizationResource(TestTokenCreator.getDomain(), new AuthDataStore(), null, null, null, null, null);
		
		try {
			// test
			testee.createObject(postRequest, request, response);
			fail("APIRuntimeException should be thrown in the previous step.");
		} catch (APIRuntimeException e) {
			assertEquals(HttpURLConnection.HTTP_BAD_REQUEST, e.getHttpStatus());
		}
		
		// verify
		verify(postRequest).getParam();
	}
	
	@Test
	public void testCreateObject_WithAuth0Code() throws Exception {
		
		// mock: HttpServletRequest - provides Authorization header
		HttpServletRequest request = mock(HttpServletRequest.class);
		String authCode = TestTokenCreator.getAuth0Code();
		when(request.getHeader("Authorization")).thenReturn("Auth0Code "+authCode);
		StringBuffer reqUrl = new StringBuffer("http://www.examples.com");
		when(request.getRequestURL()).thenReturn(reqUrl);

		// mock: HttpServletResponse
		HttpServletResponse response = mock(HttpServletResponse.class);

		// mock: Auth0Client
		Auth0Client auth0 = mock(Auth0Client.class);
		Auth0Credential auth0Cred = new Auth0Credential();
		auth0Cred.setAccessToken("AUTH0-ACCESS-TOKEN-DUMMY");
		auth0Cred.setIdToken("AUTH0-ID-TOKEN-DUMMY");
		auth0Cred.setRefreshToken("AUTH0-REFRESH-TOKEN-DUMMY");
		auth0Cred.setTokenType("Bearer");
		when(auth0.getToken(authCode, reqUrl.toString())).thenReturn(auth0Cred);
		String newToken = "TC-JWT-TOKEN-DUMMY"; 
		
		// mock: AuthDataStore
		AuthDataStore authDataStore = spy(new AuthDataStore());
		doNothing().when(authDataStore).put(any(Authorization.class)); 
		
		// mock: ZendeskAuthPlugin
		// mock: ZendeskAuthPlugin
		final String zendeskJwt = "DUMMY-ZD-TOKEN";
		ZendeskAuthPlugin zendeskAuthPlugin = spy(new ZendeskAuthPlugin(){
			@Override public Authorization process(Authorization auth) {
				auth.setZendeskJwt(zendeskJwt);
				return auth;
			}});
		
		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, auth0, null, null, null, null));
		testee.setZendeskAuthPlugin(zendeskAuthPlugin);
		
		doReturn(newToken).when(testee).createJWTToken(auth0Cred.getIdToken()); // mock::createJWTToken()
		doNothing().when(testee).processTCCookies(any(Authorization.class), any(HttpServletRequest.class), any(HttpServletResponse.class), eq(false));
		doNothing().when(testee).updateLastLoginDate(any(Authorization.class));
		
		// test
		ApiResponse result = testee.createObject(null, request, response);
		
		// verify result
		// API version
		assertEquals(ApiVersion.v3, result.getVersion());
		// result
		assertNotNull(result.getResult());
		assertEquals(HttpURLConnection.HTTP_OK, (int)result.getResult().getStatus());
		assertTrue("ApiResponse.Result should be success.", result.getResult().getSuccess());
		// authorization
		Authorization auth = (Authorization)result.getResult().getContent();
		assertNotNull(auth);
		assertEquals(newToken, auth.getToken());
		assertEquals(auth0Cred.getIdToken(), auth.getExternalToken());
		assertEquals(auth0Cred.getRefreshToken(), auth.getRefreshToken());
		assertEquals("1", auth.getTarget());
		assertEquals(zendeskJwt, auth.getZendeskJwt());
		
		// verify mocks
		verify(request).getRequestURL();
		verify(auth0).getToken(authCode, reqUrl.toString());
		verify(authDataStore).put(auth);
		verify(zendeskAuthPlugin).process(auth);
		verify(testee).createJWTToken(auth0Cred.getIdToken());
		verify(testee).processTCCookies(auth, request, response, false);
		verify(testee).addZendeskInfo(auth);
		verify(testee).updateLastLoginDate(auth);
	}

	private void testCreateObject_WithAuth0Code_InvalidHeader(HttpServletRequest mockRequest, int expectedStatusCode) throws Exception {
		// mock: Auth0Client
		Auth0Client auth0 = mock(Auth0Client.class);
		
		// target
		AuthorizationResource testee = new AuthorizationResource(TestTokenCreator.getDomain(), new AuthDataStore(), auth0, null, null, null, null);
		
		// test
		try {
			testee.createObject(null, mockRequest, null);
			fail("Exception should be thrown in the previous step.");
		} catch (APIRuntimeException e) {
			assertEquals(expectedStatusCode, e.getHttpStatus());
		}
		
		// verify mocks
		// - jwt token should be taken from request header.
		verify(mockRequest).getHeader("Authorization");
		// - should not request to gain token in Auth0.
		verify(auth0, never()).getToken(anyString(), anyString());
	}

	@Test
	public void testCreateObject_WithAuth0Code_400WhenHeaderIsNotSet() throws Exception {
		
		// mock: HttpServletRequest - provides no Authorization header
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader("Authorization")).thenReturn(null);
		
		testCreateObject_WithAuth0Code_InvalidHeader(request, HttpURLConnection.HTTP_BAD_REQUEST);
	}
	
	@Test
	public void testCreateObject_WithAuth0Code_400WhenHeaderIsInvalidCode() throws Exception {
		
		// mock: HttpServletRequest - provides no Authorization header
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader("Authorization")).thenReturn("Bearer ABCDEFGHIJKLMNOPQRSTUVWXYZ");
		
		testCreateObject_WithAuth0Code_InvalidHeader(request, HttpURLConnection.HTTP_BAD_REQUEST);
	}
	
	@Test
	public void testCreateObject_WithClientId() throws Exception {
		// data
		Authorization auth = new Authorization();
		auth.setId(new TCID(auth.hashCode()));
		auth.setToken("TC-JWT-TOKEN-DUMMY");
		auth.setTarget("1");
		
		// mock: HttpServletRequest
		HttpServletRequest request = mock(HttpServletRequest.class);
		
		// mock: AuthDataStore
		AuthDataStore authDataStore = spy(new AuthDataStore());
		doNothing().when(authDataStore).put(auth);
		
		// mock: ServiceAccountAuthenticator
		ServiceAccount serviceAccount = new ServiceAccount();
		serviceAccount.setContextUserId("SERVICE-USER-ID-DUMMY");
		serviceAccount.setClientId("SERVICE-CLIENT-ID-DUMMY");
		serviceAccount.setClientSecret("SERVICE-CLIENT-SECRET-DUMMY");
		ServiceAccountAuthenticator serviceAccountAuthenticator = mock(ServiceAccountAuthenticator.class);
		when(serviceAccountAuthenticator.authenticate(serviceAccount.getClientId(), serviceAccount.getClientSecret())).thenReturn(serviceAccount);

		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, null, null, serviceAccountAuthenticator, null, null));
		doReturn(auth).when(testee).createAuthorization(serviceAccount.getContextUserId()); // mock for createAuthorization(systenUserId)
		doNothing().when(testee).updateLastLoginDate(auth);
		
		// test
		ApiResponse response = testee.createObject(
				serviceAccount.getClientId(),
				serviceAccount.getClientSecret(),
				request);
		
		// verify result
		// API version
		assertEquals(ApiVersion.v3, response.getVersion());
		// result
		assertNotNull(response.getResult());
		assertEquals(HttpURLConnection.HTTP_OK, (int)response.getResult().getStatus());
		assertTrue("ApiResponse.Result should be success.", response.getResult().getSuccess());
		// authorization
		Authorization authInResult = (Authorization)response.getResult().getContent();
		assertNotNull(authInResult);
		assertEquals(auth, authInResult);
		
		// verify mocks
		verify(testee).createAuthorization(serviceAccount.getContextUserId());
		verify(testee).updateLastLoginDate(auth);
		verify(authDataStore).put(auth);
		verify(serviceAccountAuthenticator).authenticate(serviceAccount.getClientId(), serviceAccount.getClientSecret());
	}
	
	@Test
	public void testCreateObject_WithClientId_400WhenClientIdIsMissing() throws Exception {
		
		// mock
		HttpServletRequest request = mock(HttpServletRequest.class);
		AuthDataStore authDataStore = mock(AuthDataStore.class);
		ServiceAccountAuthenticator serviceAccountAuthenticator = mock(ServiceAccountAuthenticator.class);

		// target
		AuthorizationResource testee = new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, null, null, serviceAccountAuthenticator, null, null);
		
		try {
			// test
			testee.createObject(null, // client-id
					"SERVICE-CLIENT-SECRET-DUMMY", request);
			fail("APIRuntimeException should be thrown in the previous step.");
		} catch (APIRuntimeException e) {
			assertEquals(HttpURLConnection.HTTP_BAD_REQUEST, e.getHttpStatus());
		}
		
		// verify
		verify(authDataStore, never()).put(any(Authorization.class));
		verify(serviceAccountAuthenticator, never()).authenticate(anyString(), anyString());
	}
	
	@Test
	public void testCreateObject_WithClientId_400WhenSecretIsMissing() throws Exception {
		
		// mock
		HttpServletRequest request = mock(HttpServletRequest.class);
		AuthDataStore authDataStore = mock(AuthDataStore.class);
		ServiceAccountAuthenticator serviceAccountAuthenticator = mock(ServiceAccountAuthenticator.class);

		// target
		AuthorizationResource testee = new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, null, null, serviceAccountAuthenticator, null, null);
		
		try {
			// test
			testee.createObject("SERVICE-CLIENT-ID-DUMMY", null, // client-secret
					request);
			fail("APIRuntimeException should be thrown in the previous step.");
		} catch (APIRuntimeException e) {
			assertEquals(HttpURLConnection.HTTP_BAD_REQUEST, e.getHttpStatus());
		}
		
		// verify
		verify(authDataStore, never()).put(any(Authorization.class));
		verify(serviceAccountAuthenticator, never()).authenticate(anyString(), anyString());
	}
	
	@Test
	public void testCreateObject_WithClientId_401WhenClientIsUnauthenticated() throws Exception {
		// mock
		HttpServletRequest request = mock(HttpServletRequest.class);
		AuthDataStore authDataStore = mock(AuthDataStore.class);
		ServiceAccountAuthenticator serviceAccountAuthenticator = mock(ServiceAccountAuthenticator.class);
		when(serviceAccountAuthenticator.authenticate(anyString(), anyString())).thenReturn(null); // unauthenticated

		// target
		AuthorizationResource testee = new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, null, null, serviceAccountAuthenticator, null, null);
		
		try {
			// test
			testee.createObject("SERVICE-CLIENT-ID-DUMMY", "SERVICE-CLIENT-SECRET-DUMMY", request);
			fail("APIRuntimeException should be thrown in the previous step.");
		} catch (APIRuntimeException e) {
			assertEquals(HttpURLConnection.HTTP_UNAUTHORIZED, e.getHttpStatus());
		}
		
		// verify
		verify(authDataStore, never()).put(any(Authorization.class));
		verify(serviceAccountAuthenticator).authenticate(eq("SERVICE-CLIENT-ID-DUMMY"), eq("SERVICE-CLIENT-SECRET-DUMMY"));
	}
	
	@Test
	public void testDeleteObject() throws Exception {
		// test data
		String targetId = "1";
		String token = "JWT-TOKEN-DUMMY";
		String auth0Token = "AUTH0-TOKEN-DUMMY";
		String refreshToken = "REFRESH-TOKEN-DUMMY";
		Authorization auth = new Authorization();
		auth.setToken(token);
		auth.setRefreshToken(refreshToken);
		auth.setExternalToken(auth0Token);
		
		// mock: HttpServletRequest - provides Authorization header
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader("Authorization")).thenReturn("Bearer "+token);
		
		// mock: HttpServletResponse
		HttpServletResponse response = mock(HttpServletResponse.class);

		// mock: Auth0Client
		Auth0Client auth0 = mock(Auth0Client.class);
		
		// mock: AuthDataStore - storing Authorization object
		AuthDataStore authDataStore = mock(AuthDataStore.class);
		when(authDataStore.get(token, targetId)).thenReturn(auth);
		
		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, auth0, null, null, null, null));
		
		// test
		ApiResponse resp = testee.deleteObject(null, targetId, request, response);
		
		// verify result
		// API version
		assertEquals(ApiVersion.v3, resp.getVersion());
		// result
		assertNotNull(resp.getResult());
		assertEquals(HttpURLConnection.HTTP_OK, (int)resp.getResult().getStatus());
		assertTrue("ApiResponse.Result should be success.", resp.getResult().getSuccess());
		
		// verify mocks
		// - jwt token should be taken from request header.
		verify(request).getHeader("Authorization");
		// - Authorization object should be removed from the store.
		verify(authDataStore).get(token, targetId);
		verify(authDataStore).delete(token, targetId);
		// - refresh token should be revoked in Auth0. 
		verify(auth0).revokeRefreshToken(auth0Token, auth.getRefreshToken());
		// - cookies(tcjwt&tcsso) shoule be deleted.
		verify(testee).deleteTCCookies(response);
	}
	
	@Test
	public void testDeleteObject_401WhenNoAuthHeaeder() throws Exception {
		
		// mock: HttpServletRequest - provides no Authorization header
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader("Authorization")).thenReturn(null);
		// mock: HttpServletResponse
		HttpServletResponse response = mock(HttpServletResponse.class);
		
		// mock: Auth0Client
		Auth0Client auth0 = mock(Auth0Client.class);
		// mock: AuthDataStore
		AuthDataStore authDataStore = mock(AuthDataStore.class);
		
		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, auth0, null, null, null, null));
		
		// test
		try {
			testee.deleteObject(null, "1", request, response);
			fail("Exception should be thrown in the previous step.");
		} catch (APIRuntimeException e) {
			assertEquals(HttpURLConnection.HTTP_UNAUTHORIZED, e.getHttpStatus());
		}
		
		// verify mocks
		// - jwt token should be taken from request header.
		verify(request).getHeader("Authorization");
		// - should not delete Authorization in the store
		verify(authDataStore, never()).delete(anyString(), anyString());
		// - should not request to gain token in Auth0.
		verify(auth0, never()).revokeRefreshToken(anyString(), anyString());
		
		verify(testee, never()).deleteTCCookies(response);
	}
	
	@Test
	public void testDeleteObject_AlreadyLoggedOut() throws Exception {
		
		// mock: HttpServletRequest - provides no Authorization header
		String token = "JWT-TOKEN-DUMMY";
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader("Authorization")).thenReturn("Bearer "+token);
		// mock: HttpServletResponse
		HttpServletResponse response = mock(HttpServletResponse.class);

		// mock: Auth0Client
		Auth0Client auth0 = mock(Auth0Client.class);
		// mock: AuthDataStore - return null when the client has already logged out
		AuthDataStore authDataStore = mock(AuthDataStore.class);
		when(authDataStore.get(token, "1")).thenReturn(null);
		
		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, auth0, null, null, null, null));
		
		// test
		ApiResponse resp = testee.deleteObject(null, "1", request, response);
		
		// verify result
		// API version
		assertEquals(ApiVersion.v3, resp.getVersion());
		// result
		assertNotNull(resp.getResult());
		assertEquals(HttpURLConnection.HTTP_OK, (int)resp.getResult().getStatus());
		assertTrue("ApiResponse.Result should be success.", resp.getResult().getSuccess());
		
		// verify mocks
		// - jwt token should be taken from request header.
		verify(request).getHeader("Authorization");
		// - should not delete Authorization in the store
		verify(authDataStore, never()).delete(anyString(), anyString());
		// - should not request to gain token in Auth0.
		verify(auth0, never()).revokeRefreshToken(anyString(), anyString());
		// - cookies(tcjwt&tcsso) should be deleted
		verify(testee).deleteTCCookies(response);
	}
	
	/**
     * Test get access token by authorization_ code
     *
     * @throws Exception if any error occurs
     */
	@Test
    public void test_getTokenByAuthorizationCode() throws Exception {
	    String code = "code";
        String redirectUrl = "redirectUrl";
        String state = "state";
        
        Auth0Credential credential = new Auth0Credential();
        credential.setAccessToken("access");
        credential.setRefreshToken("refresh");

		HttpServletRequest request = mock(HttpServletRequest.class);
		final Map<String, Cookie> cookies = new HashMap<String, Cookie>();
		HttpServletResponseWrapper response = spy(new HttpServletResponseWrapper(mock(HttpServletResponse.class)) {
			@Override
			public void addCookie(Cookie cookie) {
				cookies.put(cookie.getName(), cookie);
			}
		});

        // mock: Auth0Client
        Auth0Client auth0New = mock(Auth0Client.class);
        when(auth0New.getToken(code, Utils.getFullURL(request))).thenReturn(credential);
        
        // mock: AuthDataStore - storing Authorization object
        AuthDataStore authDataStore = mock(AuthDataStore.class);
        
        CacheService cacheService = mock(CacheService.class);
        doReturn(state).when(cacheService).get(AuthorizationResource.AUTH0_STATE_CACHE_PREFIX_KEY + state);
        UserDAO userDAO = mock(UserDAO.class);
        // target (with mock impl on createJWTToken())
        AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, null, auth0New, null, userDAO, null, cacheService));

        // test
        testee.getTokenByAuthorizationCode(code, redirectUrl, state, request, response);

		assertTrue(cookies.containsKey("tcjwt"));
		assertTrue(cookies.containsKey("tcsso"));
		assertTrue(cookies.containsKey("v3jwt"));
        verify(cacheService).put("access", "refresh");
    }
	
	@Test
	public void testGetObjects() throws Exception {

		String oldToken = TestTokenCreator.getPrimaryJWTToken();
		String newToken = TestTokenCreator.getSecondaryJWTToken();
		Authorization auth = new Authorization();
		auth.setTarget("1");
		auth.setToken(oldToken);
		auth.setExternalToken(TestTokenCreator.getPrimaryAuth0JWT());
		
		// mock: HttpServletRequest - provides Authorization header
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader("Authorization")).thenReturn("Bearer "+auth.getToken());
		// mock: HttpServletResponse
		HttpServletResponse response = mock(HttpServletResponse.class);

		// mock: Auth0Client
		Auth0Client auth0 = mock(Auth0Client.class);
		// mock: AuthDataStore - storing Authorization object
		AuthDataStore authDataStore = mock(AuthDataStore.class);
		when(authDataStore.get(auth.getToken(), "1")).thenReturn(auth);
		
		// target (with mock impl on createJWTToken())
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, auth0, null, null, null, null));
		// create new token from auth0-token
		doReturn(newToken).when(testee).createJWTToken(auth.getExternalToken());
		doReturn(TestTokenCreator.getSecret()).when(testee).getSecret();
		doNothing().when(testee).processTCCookies(auth, request, response, false);
		
		
		// test
		ApiResponse resp = testee.getObject(new TCID(auth.getTarget()), null, request, response);

		// verify result
		assertEquals(newToken, auth.getToken());
		// API version
		assertEquals(ApiVersion.v3, resp.getVersion());
		// result
		assertNotNull(resp.getResult());
		assertEquals(HttpURLConnection.HTTP_OK, (int)resp.getResult().getStatus());
		assertTrue("ApiResponse.Result should be success.", resp.getResult().getSuccess());
		
		// verify mocks
		// - jwt token should be taken from request header.
		verify(request).getHeader("Authorization");
		// - new authorization should be stored in the store
		verify(authDataStore).put(auth);
		// - verify that mock was used as expected.
		verify(testee).createJWTToken(auth.getExternalToken());
		verify(testee).processTCCookies(auth, request, response, false);

	}
	
	@Test
	public void testGetObjects_WithAuth0JWT() throws Exception {

		String newToken = TestTokenCreator.getSecondaryJWTToken();
		String auth0Token = TestTokenCreator.getPrimaryAuth0JWT();
		
		// mock: HttpServletRequest - provides Authorization header
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader("Authorization")).thenReturn("Bearer "+auth0Token);
		// mock: HttpServletResponse - provides Authorization header
		HttpServletResponse response = mock(HttpServletResponse.class);

		// mock: Auth0Client
		Auth0Client auth0 = mock(Auth0Client.class);
		// mock: AuthDataStore - storing Authorization object
		AuthDataStore authDataStore = mock(AuthDataStore.class);
		
		// target (with mock impl on createJWTToken())
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, auth0, null, null, null, null));
		// create new token from auth0-token
		doReturn(newToken).when(testee).createJWTToken(auth0Token);
		doNothing().when(testee).processTCCookies(any(Authorization.class), eq(request), eq(response), any(boolean.class));
		
		// test
		ApiResponse resp = testee.getObject(new TCID("1"), null, request, response);
		Authorization auth = (Authorization)resp.getResult().getContent();
		// verify result
		assertEquals(newToken, auth.getToken());
		// API version
		assertEquals(ApiVersion.v3, resp.getVersion());
		// result
		assertNotNull(resp.getResult());
		assertEquals(HttpURLConnection.HTTP_OK, (int)resp.getResult().getStatus());
		assertTrue("ApiResponse.Result should be success.", resp.getResult().getSuccess());
		
		// verify mocks
		// - jwt token should be taken from request header.
		verify(request).getHeader("Authorization");
		// - new authorization should NOT be stored in the store (since it doesn't have access/refresh token)
		verify(authDataStore, never()).put(auth);
		// - verify that mock was used as expected.
		verify(testee).createJWTToken(auth0Token);
		verify(testee).processTCCookies(any(Authorization.class), eq(request), eq(response), any(boolean.class));
	}
	
	@Test
	public void testGetObjects_TokenShouldBeRefreshedWhenAuth0TokenIsExpired() throws Exception {
		
		String oldToken = TestTokenCreator.getPrimaryJWTToken();
		String newToken = TestTokenCreator.getSecondaryJWTToken();
		Authorization auth = new Authorization();
		auth.setTarget("1");
		auth.setToken(oldToken);
		auth.setExternalToken(TestTokenCreator.getPrimaryAuth0JWT());
		auth.setRefreshToken(TestTokenCreator.getRefreshToken());
		
		// mock: HttpServletRequest - provides Authorization header
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader("Authorization")).thenReturn("Bearer "+auth.getToken());
		// mock: HttpServletResponse
		HttpServletResponse response = mock(HttpServletResponse.class);

		// mock: Auth0Client
		Auth0Client auth0 = mock(Auth0Client.class);
		// getting new token with refresh-token from auth0
		Auth0Credential newCred = new Auth0Credential();
		newCred.setIdToken(TestTokenCreator.getSecondaryAuth0JWT());
		when(auth0.refresh(auth.getRefreshToken())).thenReturn(newCred);
		
		// mock: AuthDataStore - storing Authorization object
		AuthDataStore authDataStore = mock(AuthDataStore.class);
		when(authDataStore.get(auth.getToken(), auth.getTarget())).thenReturn(auth);

		// target (with mock impl on createJWTToken())
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, auth0, null, null, null, null));
		// token is expired.
		doThrow(new com.appirio.tech.core.api.v3.util.jwt.TokenExpiredException("expired")).when(testee).createJWTToken(auth.getExternalToken());
		doReturn(newToken).when(testee).createJWTToken(newCred.getIdToken());
		doReturn(TestTokenCreator.getSecret()).when(testee).getSecret();
		doNothing().when(testee).processTCCookies(auth, request, response, false);

		// test
		ApiResponse resp = testee.getObject(new TCID(auth.getTarget()), null, request, response);

		// verify result
		// API version
		assertEquals(ApiVersion.v3, resp.getVersion());
		// result
		assertNotNull(resp.getResult());
		assertEquals(HttpURLConnection.HTTP_OK, (int)resp.getResult().getStatus());
		assertTrue("ApiResponse.Result should be success.", resp.getResult().getSuccess());
		
		// jwt token should be updated with newly created jwt-token with new id-token from auth0.
		assertEquals(newToken, auth.getToken());
		
		// verify mocks
		// - jwt token should be taken from request header.
		verify(request).getHeader("Authorization");
		// - new authorization should be stored in the store
		verify(authDataStore).put(auth);
		// - token should be refreshed with refresh-token in auth0
		verify(auth0).refresh(auth.getRefreshToken());
		// - verify that mock was used as expected.
		verify(testee).createJWTToken(auth.getExternalToken());
		verify(testee).createJWTToken(newCred.getIdToken());
		verify(testee).processTCCookies(auth, request, response, false);
	}
	
	/**
	 * Test for COR-236(https://appirio.atlassian.net/browse/COR-236)<br>
	 * 
	 */
	@Test
	public void testGetObjects_401WhenSessionIsExpiredInCache() throws Exception {
		
		// data
		String oldToken = TestTokenCreator.getPrimaryJWTToken();
		Authorization auth = new Authorization();
		auth.setTarget("1");
		auth.setToken(oldToken);
		auth.setExternalToken(TestTokenCreator.getPrimaryAuth0JWT());
		auth.setRefreshToken(TestTokenCreator.getRefreshToken());
		
		// mock: HttpServletRequest - provides Authorization header
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader("Authorization")).thenReturn("Bearer "+auth.getToken());

		// mock: Auth0Client
		Auth0Client auth0 = mock(Auth0Client.class);
		
		// mock: AuthDataStore - storing Authorization object
		int expSec = 1;
		long expMSec = expSec * 1000L;
		AuthDataStore authDataStore = spy(new AuthDataStore());
		authDataStore.setExpirySeconds(1); // cache is expired after 1 second interval
		authDataStore.put(auth); // putting auth in the cache in advance. (emulating Login)
		
		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, auth0, null, null, null, null));
		doReturn(true).when(testee).isIssuerSameDomain(auth.getToken());
		doReturn(TestTokenCreator.getSecret()).when(testee).getSecret();
		
		// test
		try {
			Thread.sleep(expMSec); // waiting for cache expiration
			testee.getObject(new TCID(auth.getTarget()), null, request, null);
			fail("Exception should be thrown in the previous step.");
		} catch (APIRuntimeException e) {
			assertEquals(HttpURLConnection.HTTP_UNAUTHORIZED, e.getHttpStatus());
			assertEquals("Unauthorized", e.getMessage());
		}

		// verify mocks
		// - jwt token should be taken from request header.
		verify(request).getHeader("Authorization");
		verify(authDataStore).get(oldToken, auth.getTarget());
	}
	
	@Test
	public void testGetObjects_401WhenNoAuthHeaeder() throws Exception {
		
		// mock: HttpServletRequest - provides no Authorization header
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader("Authorization")).thenReturn(null);
		// mock: HttpServletResponse - provides Authorization header
		HttpServletResponse response = mock(HttpServletResponse.class);

		// mock: Auth0Client
		Auth0Client auth0 = mock(Auth0Client.class);
		// mock: AuthDataStore
		AuthDataStore authDataStore = mock(AuthDataStore.class);
		
		// target
		AuthorizationResource testee = new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, auth0, null, null, null, null);
		
		// test
		try {
			testee.getObject(new TCID("1"), null, request, response);
			fail("Exception should be thrown in the previous step.");
		} catch (APIRuntimeException e) {
			assertEquals(HttpURLConnection.HTTP_UNAUTHORIZED, e.getHttpStatus());
			assertEquals("Unauthorized", e.getMessage());
		}
		
		// verify mocks
		// - jwt token should be taken from request header.
		verify(request).getHeader("Authorization");
		// - should not do any operation on the store
		verify(authDataStore, never()).get(anyString(), anyString());
		verify(authDataStore, never()).delete(anyString(), anyString());
		verify(authDataStore, never()).put(any(Authorization.class));
		
		// - should not call any method in Auth0Client
		verify(auth0, never()).refresh(anyString());
	}
	
	@Test
	public void testGetObjects_401WhenLoggedOut() throws Exception {
		
		String token = TestTokenCreator.getPrimaryJWTToken();
		String targetId = "1";
		
		// mock: HttpServletRequest - provides no Authorization header
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader("Authorization")).thenReturn("Bearer "+token);
		// mock: HttpServletResponse - provides Authorization header
		HttpServletResponse response = mock(HttpServletResponse.class);

		// mock: Auth0Client
		Auth0Client auth0 = mock(Auth0Client.class);
		// mock: AuthDataStore
		AuthDataStore authDataStore = mock(AuthDataStore.class);
		
		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, auth0, null, null, null, null));
		doReturn(TestTokenCreator.getSecret()).when(testee).getSecret();
		
		// test
		try {
			testee.getObject(new TCID(targetId), null, request, response);
			fail("Exception should be thrown in the previous step.");
		} catch (APIRuntimeException e) {
			assertEquals(HttpURLConnection.HTTP_UNAUTHORIZED, e.getHttpStatus());
			assertEquals("Unauthorized", e.getMessage());
		}

		// verify mocks
		// - jwt token should be taken from request header.
		verify(request).getHeader("Authorization");
		// - should try to take authorization from the store (supposing to get null)
		verify(authDataStore).get(token, targetId);
		// - should not any delete/add operation on the store
		verify(authDataStore, never()).delete(anyString(), anyString());
		verify(authDataStore, never()).put(any(Authorization.class));
		
		// - should not call any method in Auth0Client
		verify(auth0, never()).refresh(anyString());
	}
	
	/**
	 * Test for COR-422(https://appirio.atlassian.net/browse/COR-422)
	 */
	@Test
	public void testGetObjects_401WhenTokenIsInvalid() throws Exception {
		
		String correctToken = TestTokenCreator.getPrimaryJWTToken();
		String antherToken = TestTokenCreator.getSecondaryJWTToken();
		String fakeToken = correctToken.split("\\.")[0] + "." + 
							antherToken.split("\\.")[1] + "." +
							correctToken.split("\\.")[2];
				
		Authorization auth = new Authorization();
		auth.setTarget("1");
		auth.setToken(fakeToken);
		auth.setExternalToken(TestTokenCreator.getPrimaryAuth0JWT());
		
		// mock: HttpServletRequest - provides Authorization header
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getHeader("Authorization")).thenReturn("Bearer "+auth.getToken());
		// mock: HttpServletResponse
		HttpServletResponse response = mock(HttpServletResponse.class);

		// mock: Auth0Client
		Auth0Client auth0 = mock(Auth0Client.class);
		// mock: AuthDataStore - storing Authorization object
		AuthDataStore authDataStore = mock(AuthDataStore.class);
		
		// target (with mock impl on createJWTToken())
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), authDataStore, auth0, null, null, null, null));
		doReturn(TestTokenCreator.getSecret()).when(testee).getSecret();
		
		// test
		try {
		    
			testee.getObject(new TCID(auth.getTarget()), null, request, response);
			fail("Exception should be thrown in the previous step.");
		} catch (APIRuntimeException e) {
			assertEquals(HttpURLConnection.HTTP_UNAUTHORIZED, e.getHttpStatus());
			assertEquals("Invalid token", e.getMessage());
		}

		// verify mocks
		// - jwt token should be taken from request header.
		verify(request).getHeader("Authorization");
		// - should not do any operation on the store
		verify(authDataStore, never()).get(anyString(), anyString());
		verify(authDataStore, never()).delete(anyString(), anyString());
		verify(authDataStore, never()).put(any(Authorization.class));
		
		// - should not call any method in Auth0Client
		verify(auth0, never()).refresh(anyString());
	}
	
	@Test
	public void testCreateAuthorization() throws Exception {

		Auth0Credential credential = new Auth0Credential();
		credential.setIdToken("AUTH0-TOKEN-DUMMY");
		credential.setRefreshToken("REFRESH-TOKEN-DUMMY");
		
		// mock: Auth0Client
		Auth0Client auth0 = mock(Auth0Client.class);
		
		// target (with mock impl on createJWTToken())
		AuthorizationResource testee = Mockito.spy(new AuthorizationResource(TestTokenCreator.getDomain(), null, auth0, null, null, null, null));
		final String newToken = "JWT-TOKEN-DUMMY";
		Mockito.doReturn(newToken).when(testee).createJWTToken(credential.getIdToken());
		
		// test
		Authorization auth = testee.createAuthorization(credential);
		
		// verify result
		assertNotNull(auth);
		// Authorization#token should be the token createJWTToken() creates.
		assertEquals(newToken, auth.getToken());
		// Authorization#externalToken should be the id-token in Auth0Credential.
		assertEquals(credential.getIdToken(), auth.getExternalToken());
		// Authorization#refreshToken should be the refresh-token in Auth0Credential.
		assertEquals(credential.getRefreshToken(), auth.getRefreshToken());
	}
	
	@Test
	public void testCreateAuthorization_WithSystemUserId() throws Exception {
		
		long uid = 123456789L;
		String userId = String.valueOf(uid);
		String secret = "SECRET-DUMMY";
		String authDomain = TestTokenCreator.getDomain();
		
		@SuppressWarnings("serial")
		List<Role> roles = new ArrayList<Role>() {
			{ add(new Role()); add(new Role()); add(new Role()); }
		};
		for(int i=0; i<roles.size(); i++)
			roles.get(i).setRoleName("ROLE-DUMMY-"+i);
		
		// mock
		RoleDAO roleDao = mock(RoleDAO.class);
		when(roleDao.getRolesBySubjectId(uid)).thenReturn(roles);
		
		// target
		AuthorizationResource testee = spy(new AuthorizationResource(authDomain, null, null, null, null, null, roleDao));
		when(testee.getSecret()).thenReturn(secret);

		// test
		Authorization result = testee.createAuthorization(userId);
		
		// verify result
		assertNotNull(result);
		assertNotNull(result.getToken());
		assertEquals("1", result.getTarget());
		
		// parsing token
		JWTToken jwt = new JWTToken(result.getToken(), secret, Utils.getValidIssuers());
		assertEquals(userId, jwt.getUserId());
		assertNotNull(jwt.getRoles());
		assertEquals(roles.size(), jwt.getRoles().size());
		for(int i=0; i<jwt.getRoles().size(); i++) {
			assertEquals(roles.get(i).getRoleName(), jwt.getRoles().get(i));
		}
		assertEquals(jwt.createIssuerFor(authDomain), jwt.getIssuer());
	}
	
	@Test
	public void testCreateJWTToken() throws Exception {
		
		// data
		String auth0Token = "AUTH0-TOKEN-DUMMY";
		Long userId = 123456L;
		User user = new User();
		user.setId(new TCID(userId));
		user.setHandle("HANDLE-DUMMY");
		user.setEmail("EMAIL-DUMMY");
		user.setActive(true);
		
		@SuppressWarnings("serial")
		List<Role> roles = new ArrayList<Role>() {
			{ add(new Role()); add(new Role()); add(new Role()); }
		};
		for(int i=0; i<roles.size(); i++)
			roles.get(i).setRoleName("ROLE-DUMMY-"+i);
			
		// mock
		UserDAO userDao = mock(UserDAO.class);
		when(userDao.findUserById(userId)).thenReturn(user);
		RoleDAO roleDao = mock(RoleDAO.class);
		when(roleDao.getRolesBySubjectId(userId)).thenReturn(roles);

		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), null, null, null, null, userDao, roleDao));
		testee.setSecret("DUMMY-SECRET");
		doReturn(String.valueOf(userId)).when(testee).getUserId(auth0Token);

		// test
		String result = testee.createJWTToken(auth0Token);

		// verify result
		assertNotNull(result);
		JWTToken jwt = new JWTToken(result, testee.getSecret(), Utils.getValidIssuers());
		assertEquals(userId, new Long(jwt.getUserId()));
		assertEquals(user.getHandle(), jwt.getHandle());
		assertEquals(user.getEmail(), jwt.getEmail());
		assertNotNull(jwt.getRoles());
		assertEquals(roles.size(), jwt.getRoles().size());
		for(int i=0; i<jwt.getRoles().size(); i++) {
			assertEquals(roles.get(i).getRoleName(), jwt.getRoles().get(i));
		}
		assertEquals(jwt.createIssuerFor(TestTokenCreator.getDomain()), jwt.getIssuer());
		
		// verify mock
		verify(testee).getUserId(auth0Token);
		verify(userDao).findUserById(userId);

	}
	
	@Test
	public void testCreateJWTToken_403WhenUserIsInactive() throws Exception {
		
		// data
		String auth0Token = "AUTH0-TOKEN-DUMMY";
		Long userId = 123456L;
		User user = new User();
		user.setId(new TCID(userId));
		user.setHandle("HANDLE-DUMMY");
		user.setEmail("EMAIL-DUMMY");
		user.setActive(false);
		
		// mock
		UserDAO userDao = mock(UserDAO.class);
		when(userDao.findUserById(123456L)).thenReturn(user);

		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), null, null, null, null, userDao, null));
		doReturn(String.valueOf(userId)).when(testee).getUserId(auth0Token);

		// test
		try {
			testee.createJWTToken(auth0Token);
			fail("APIRuntimeException should be thrown in the previous step.");
		} catch (APIRuntimeException e) {
			assertEquals(HttpServletResponse.SC_FORBIDDEN, e.getHttpStatus());
		}

		// verify mock
		verify(testee).getUserId(auth0Token);
		verify(userDao).findUserById(userId);
	}
	
	@Test
	public void testGetUserId() throws Exception {

		// data
		String auth0Token = "AUTH0-TOKEN-DUMMY";
		String userId = "123456";
		UserProfile profile = new UserProfile();
		profile.setProviderType(ProviderType.LDAP.name);
		profile.setUserId(userId);

		// mock
		UserDAO userDao = mock(UserDAO.class);
		when(userDao.getUserId(profile)).thenReturn(Long.valueOf(userId));

		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), null, null, null, null, userDao, null));
		doReturn(profile).when(testee).createProfile(auth0Token); // mock
		
		// test
		String result = testee.getUserId(auth0Token);
		
		// verify result
		assertNotNull(result);
		assertEquals(userId, result);

		// verify mock
		verify(testee).createProfile(auth0Token);
		verify(userDao).getUserId(any(UserProfile.class));
	}
	
	@Test
	public void testGetUserId_401WhenIdentityIsProvidedByUnsupportedSocialProvider() throws Exception {

		// data
		String auth0Token = "AUTH0-TOKEN-DUMMY";
		String userId = "USER-ID-DUMMY";
		UserProfile profile = new UserProfile();
		profile.setProviderType("UNKNOWN-PROVIDER"); // unknown social provider
		profile.setUserId(userId);

		// mock
		SocialUserDAO socialUserDAO = mock(SocialUserDAO.class);

		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), null, null, null, null, null, null));
		doReturn(profile).when(testee).createProfile(auth0Token); // mock
		
		// test
		try {
			testee.getUserId(auth0Token);
			fail("APIRuntimeException should be thrown in the previous step.");
		} catch (APIRuntimeException e) {
			assertEquals(HttpURLConnection.HTTP_UNAUTHORIZED, e.getHttpStatus());
		}
		
		// verify mock
		verify(testee).createProfile(auth0Token);
		// socialUserDAO should not be used when the identity is  non-social.
		verify(socialUserDAO, never()).findUserIdByProfile(any(UserProfile.class));
	}
	
	@Test
	public void testGetUserId_500WhenAuth0TokenDoesNotContainUserId() throws Exception {

		// data
		String auth0Token = "AUTH0-TOKEN-DUMMY";
		UserProfile profile = new UserProfile();
		profile.setProviderType(ProviderType.LDAP.name);
		profile.setUserId(null); // does not contain user-id

		// mock
		SocialUserDAO socialUserDAO = mock(SocialUserDAO.class);
		UserDAO userDao = mock(UserDAO.class);
		when(userDao.getUserId(any(UserProfile.class))).thenCallRealMethod();
		when(userDao.createSocialUserDAO()).thenReturn(socialUserDAO);

		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), null, null, null, null, userDao, null));
		doReturn(profile).when(testee).createProfile(auth0Token); // mock
		
		// test
		try {
			testee.getUserId(auth0Token);
			fail("APIRuntimeException should be thrown in the previous step.");
		} catch (APIRuntimeException e) {
			assertEquals(HttpURLConnection.HTTP_INTERNAL_ERROR, e.getHttpStatus());
		}
		
		// verify mock
		verify(testee).createProfile(auth0Token);
		// socialUserDAO should not be used when the identity is  non-social.
		verify(socialUserDAO, never()).findUserIdByProfile(any(UserProfile.class));
	}
	
	@Test
	public void testGetUserId_SocialUser() throws Exception {

		// data
		String auth0Token = "AUTH0-TOKEN-DUMMY";
		String userId = "1234567890";
		UserProfile profile = new UserProfile();
		profile.setUserId(userId);
		profile.setProviderType(ProviderType.FACEBOOK.name); //Social

		// mock
		SocialUserDAO socialUserDao = mock(SocialUserDAO.class);
		doReturn(Long.valueOf(userId)).when(socialUserDao).findUserIdByProfile(profile);
		UserDAO userDao = mock(UserDAO.class);
		doCallRealMethod().when(userDao).getUserId(profile);
		doReturn(socialUserDao).when(userDao).createSocialUserDAO();

		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), null, null, null, null, userDao, null));
		doReturn(profile).when(testee).createProfile(auth0Token); // mock
		
		// test
		String result = testee.getUserId(auth0Token);
		
		// verify result
		assertNotNull(result);
		assertEquals(userId, result);

		// verify mock
		verify(testee).createProfile(auth0Token);
		verify(userDao).getUserId(profile);
		verify(userDao).createSocialUserDAO();
	}
	
	@Test
	public void testGetUserId_SocialUser_401WhenSocialUserIsNotRegistered() throws Exception {

		// data
		String auth0Token = "AUTH0-TOKEN-DUMMY";
		String userId = "1234567890";
		UserProfile profile = new UserProfile();
		profile.setUserId(userId);
		profile.setProviderType(ProviderType.FACEBOOK.name); //Social

		// mock
		SocialUserDAO socialUserDao = mock(SocialUserDAO.class);
		doReturn(null).when(socialUserDao).findUserIdByProfile(profile); // there's no user in the system, which is related to identity.
		UserDAO userDao = mock(UserDAO.class);
		doCallRealMethod().when(userDao).getUserId(profile);
		doReturn(socialUserDao).when(userDao).createSocialUserDAO();

		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), null, null, null, null, userDao, null));
		doReturn(profile).when(testee).createProfile(auth0Token); // mock
		
		// test
		try {
			testee.getUserId(auth0Token);
			fail("APIRuntimeException should be thrown in the previous step.");
		} catch (APIRuntimeException e) {
			assertEquals(HttpURLConnection.HTTP_UNAUTHORIZED, e.getHttpStatus());
		}
		
		// verify mock
		verify(testee).createProfile(auth0Token);
		verify(userDao).getUserId(profile);
		verify(userDao).createSocialUserDAO();
	}
	
	@Test
	public void testCreateProfile() throws Exception {
		// data
		/* {
		    "identities": [
		        {
		            "connection": "LDAP", 
		            "isSocial": false, 
		            "provider": "ad", 
		            "user_id": "LDAP|1234567890"
		        }
		    ], 
		    "nickname": "..."
			} 
		*/
		List<Map<String, Object>> identities = new ArrayList<Map<String, Object>>();
		LinkedHashMap<String, Object> identity = new LinkedHashMap<String, Object>();
		identities.add(identity);
		identity.put("user_id", "LDAP|1234567890");
		identity.put("provider", "ad");
		identity.put("connection", "LDAP");
		identity.put("isSocial", false);
		
		@SuppressWarnings("unchecked")
		LinkedHashMap<String, Object> expectedMap = (LinkedHashMap<String, Object>)identity.clone();
		expectedMap.put("user_id", "1234567890"); // should extract UserID part
		
		// test
		testCreateProfile(identities, expectedMap);
	}
	
	@Test
	public void testCreateProfile_UnsupportedProviderShouldBeIgnored() throws Exception {
		// data
		/* {
		    "identities": [
		        {
		            "connection": "unknown", 
		            "isSocial": false, 
		            "provider": "unknown", 
		            "user_id": "..."
		        }
		        {
		            "connection": "LDAP", 
		            "isSocial": false, 
		            "provider": "ad", 
		            "user_id": "LDAP|1234567890"
		        }
		    ], 
		    "nickname": "..."
			} 
		*/
		
		List<Map<String, Object>> identities = new ArrayList<Map<String, Object>>();
		
		Map<String, Object> identityUnknown = new LinkedHashMap<String, Object>();
		identities.add(identityUnknown);
		identityUnknown.put("user_id", "unknown|1234567890abc"); // this should be ignored.
		identityUnknown.put("provider", "unknown");
		identityUnknown.put("connection", "unknown");
		identityUnknown.put("isSocial", false);

		LinkedHashMap<String, Object> identityAD = new LinkedHashMap<String, Object>();
		identities.add(identityAD);
		identityAD.put("user_id", "LDAP|1234567890");
		identityAD.put("provider", "ad");
		identityAD.put("connection", "LDAP");
		identityAD.put("isSocial", false);
		
		@SuppressWarnings("unchecked")
		LinkedHashMap<String, Object> expectedMap = (LinkedHashMap<String, Object>)identityAD.clone();
		expectedMap.put("user_id", "1234567890"); // should extract UserID part

		// test
		testCreateProfile(identities, expectedMap);
	}
	
	@Test
	public void testCreateProfile_IdentityProvidedByAuth0WithTCUserDatabaseConnectionShouldBeAdopted() throws Exception {
		// data
		/* {
		    "identities": [
		        {
		            "connection": "TC-User-Database", 
		            "isSocial": false, 
		            "provider": "auth0", 
		            "user_id": "1234567890"
		        }
		    ], 
		    "nickname": "..."
			} 
		*/
		List<Map<String, Object>> identities = new ArrayList<Map<String, Object>>();
		Map<String, Object> identity = new LinkedHashMap<String, Object>();
		identities.add(identity);
		identity.put("user_id", "1234567890");
		identity.put("provider", "auth0");
		identity.put("connection", "TC-User-Database");
		identity.put("isSocial", false);

		// test
		testCreateProfile(identities, identity);
	}
	
	@Test
	public void testCreateProfile_IdentityProvidedByAuth0WithUnsupportedConnectionShouldBeIgnored() throws Exception {
		// data
		/* {
		    "identities": [
		        {
		            "connection": "User-Password-Connection", // unsupported
		            "isSocial": false, 
		            "provider": "auth0", 
		            "user_id": "..."
		        },
		        {
		            "connection": "github", 
		            "isSocial": true, 
		            "provider": "github", 
		            "user_id": "..."
		        }
		    ], 
		    "nickname": "...",
		    "screen_name": "..."
			} 
		*/
		List<Map<String, Object>> identities = new ArrayList<Map<String, Object>>();
		Map<String, Object> identityAuth0 = new LinkedHashMap<String, Object>();
		identities.add(identityAuth0);
		identityAuth0.put("user_id", "1234567890");
		identityAuth0.put("provider", "auth0");
		identityAuth0.put("connection", "User-Password-Connection");
		identityAuth0.put("isSocial", false);
		
		Map<String, Object> identitySocial = new LinkedHashMap<String, Object>();
		identities.add(identitySocial);
		identitySocial.put("user_id", "1234567891");
		identitySocial.put("provider", "github");
		identitySocial.put("connection", "github");
		identitySocial.put("isSocial", true);

		// test
		testCreateProfile(identities, identitySocial);
	}
	

	
	protected void testCreateProfile(List<Map<String, Object>> identities, Map<String, Object> expected) throws Exception {
		
		String auth0Token = "AUTH0-TOKEN-DUMMY";
		String userName = "nickname123";

		Map<String, Object> jwtContents = new HashMap<String, Object>();
		jwtContents.put("nickname", userName);
		jwtContents.put("identities", identities);

		// mock
		Auth0Client auth0 = mock(Auth0Client.class);
		when(auth0.verifyToken(auth0Token)).thenReturn(jwtContents);
		
		// target
		AuthorizationResource testee = new AuthorizationResource(TestTokenCreator.getDomain(), null, auth0, null, null, null, null);
		
		// test
		UserProfile result = testee.createProfile(auth0Token);
		
		// verify result
		assertNotNull(result);
		assertEquals(expected.get("user_id"), result.getUserId());
		assertEquals(userName, result.getName());
		assertEquals(expected.get("provider"), result.getProviderType());
		assertEquals(expected.get("connection"), result.getProvider());
		
		// verify mock
		verify(auth0).verifyToken(auth0Token);
	}
	
	@Test
	public void testCreateProfile_NoIdentity() throws Exception {
		String auth0Token = "AUTH0-TOKEN-DUMMY";
		String userId = "123456";
		String userName = "nickname123";
		String provider = "ad";

		Map<String, Object> jwtContents = new HashMap<String, Object>();
		jwtContents.put("nickname", userName);
		jwtContents.put("sub", provider+"|LDAP|"+userId);
		
		// mock
		Auth0Client auth0 = mock(Auth0Client.class);
		when(auth0.verifyToken(auth0Token)).thenReturn(jwtContents);
		
		// target
		AuthorizationResource testee = new AuthorizationResource(TestTokenCreator.getDomain(), null, auth0, null, null, null, null);
		
		// test
		UserProfile result = testee.createProfile(auth0Token);
		
		// verify result
		assertNotNull(result);
		assertEquals(userId, result.getUserId());
		assertEquals(userName, result.getName());
		assertEquals(provider, result.getProviderType());
		
		// verify mock
		verify(auth0).verifyToken(auth0Token);
	}
	
	@Test
	public void testRefresh() throws Exception {
		String refreshToken = "REFRESH-TOKEN-DUMMY";
		String newAuth0Token = "NEW-AUTH0-TOKEN-DUMMY";
		String newToken = "NEW-JWT-TOKEN-DUMMY";
		
		// mock: Auth0Client
		Auth0Client auth0 = mock(Auth0Client.class);
		Auth0Credential cred = new Auth0Credential();
		cred.setIdToken(newAuth0Token);
		when(auth0.refresh(refreshToken)).thenReturn(cred);
		
		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), null, auth0, null, null, null, null));
		doReturn(newToken).when(testee).createJWTToken(newAuth0Token);
		
		// test
		String result = testee.refresh(refreshToken);
		
		// verify result
		assertEquals(newToken, result);
		
		// verify mocks
		verify(auth0).refresh(refreshToken);
	}
	
	@Test
	public void testCreateRedirectURL() {
		
		// mock
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		StringBuffer reqUrl = new StringBuffer("http://www.topcoder.com/v3/users");
		when(request.getRequestURL()).thenReturn(reqUrl);
		when(request.getHeader("Referer")).thenReturn("https://www.topcoder.com/sample/index.html");
		
		// target
		AuthorizationResource testee = new AuthorizationResource(TestTokenCreator.getDomain(), null, null, null, null, null, null);
		
		String result = testee.createRedirectURL(request);
		
		assertNotNull(result);
		assertEquals("https://www.topcoder.com/v3/users", result);
		
		verify(request).getRequestURL();
		verify(request).getHeader("Referer");
	}
	
	@Test
	public void testCreateRedirectURL_NoReferer() {
		
		// mock
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		StringBuffer reqUrl = new StringBuffer("http://www.topcoder.com/v3/users");
		when(request.getRequestURL()).thenReturn(reqUrl);
		when(request.getHeader("Referer")).thenReturn(null);
		
		// target
		AuthorizationResource testee = new AuthorizationResource(TestTokenCreator.getDomain(), null, null, null, null, null, null);
		
		String result = testee.createRedirectURL(request);
		
		assertNotNull(result);
		assertEquals(reqUrl.toString(), result); // same url as the requested url
		
		verify(request).getRequestURL();
		verify(request).getHeader("Referer");
	}
	
	@Test
	public void testProcessTCCookies() throws Exception {
		testProcessTCCookies(false);
	}

	@Test
	public void testProcessTCCookies_RememberMe() throws Exception {
		testProcessTCCookies(true);
	}

	public void testProcessTCCookies(boolean rememberMe) throws Exception {
		// data
		Authorization auth = new Authorization();
		auth.setToken(TestTokenCreator.getPrimaryJWTToken());
		auth.setExternalToken(TestTokenCreator.getPrimaryAuth0JWT());
		auth.setRefreshToken(TestTokenCreator.getRefreshToken());
		Long userId = 123456L;
		
		// mock
		HttpServletRequest request = mock(HttpServletRequest.class);
		final Map<String, Cookie> cookies = new HashMap<String, Cookie>();
		HttpServletResponseWrapper response = spy(new HttpServletResponseWrapper(mock(HttpServletResponse.class)) {
			@Override
			public void addCookie(Cookie cookie) {
				cookies.put(cookie.getName(), cookie);
			}
		});
		
		// mock: userDao
		UserDAO userDao = mock(UserDAO.class);
		String ssoToken = "SSO-TOKEN-DUMMY";
		doReturn(ssoToken).when(userDao).generateSSOToken(userId);
		
		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), null, null, null, null, userDao, null));
		Integer expirySeconds = 180;
		testee.setCookieExpirySeconds(expirySeconds);
		doReturn(rememberMe).when(testee).getRememberMe(request); // mock
		doReturn(userId).when(testee).extractUserId(auth); // mock

		// test
		testee.processTCCookies(auth, request, response, false);

		// verify
		verify(testee).getRememberMe(request);
		// 2 cookies should be created and added to the response
		if(rememberMe) {
			verify(testee).createCookie(eq("tcjwt"), eq(auth.getExternalToken()), eq(MAX_COOKIE_EXPIRY_SECONDS));
			verify(testee).createCookie(eq("tcsso"), eq(ssoToken), eq(MAX_COOKIE_EXPIRY_SECONDS));
		} else {
			verify(testee).createCookie(eq("tcjwt"), eq(auth.getExternalToken()), eq(expirySeconds));
			verify(testee).createCookie(eq("tcsso"), eq(ssoToken), eq(expirySeconds));
		}
		verify(response, times(2)).addCookie(any(Cookie.class));
		
		int age = rememberMe ? MAX_COOKIE_EXPIRY_SECONDS : expirySeconds;
		String domain = "."+TestTokenCreator.getDomain().toLowerCase();
		
		// cookie(tcjwt)
		assertTrue(cookies.containsKey("tcjwt"));
		Cookie tcjwt = cookies.get("tcjwt");
		assertEquals(age, tcjwt.getMaxAge());
		assertEquals(domain, tcjwt.getDomain().toLowerCase());
		assertEquals(auth.getExternalToken(), tcjwt.getValue());

		// cookie(tcsso)
		assertTrue(cookies.containsKey("tcsso"));
		Cookie tcsso = cookies.get("tcsso");
		assertEquals(age, tcsso.getMaxAge());
		assertEquals(domain, tcsso.getDomain().toLowerCase());
		assertEquals(ssoToken, tcsso.getValue());
	}
	
	@Test
	public void testGetRememberMe() {
		testGetRememberMe(true);
		testGetRememberMe(false);
	}
	
	public void testGetRememberMe(boolean rememberMe) {
		// data
		Cookie cookieRM = new Cookie("rememberMe", ""+rememberMe);
		Cookie cookieOther = new Cookie("anotherCookie", "value");
		Cookie[] cookies = new Cookie[]{cookieRM, cookieOther};
		
		// mock
		HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
		when(request.getCookies()).thenReturn(cookies);
		
		// testee
		AuthorizationResource testee = new AuthorizationResource(TestTokenCreator.getDomain(), null, null, null, null, null, null);
		
		// test
		boolean result = testee.getRememberMe(request);
		
		// verify
		assertEquals("getRememberMe() should return true when the request has the cookie(rememberMe, " + rememberMe + ")",
					rememberMe, result);
		verify(request).getCookies();
	}
	
	@Test
	public void testDeleteTCCookies() throws Exception {
		
		// mock
		final Map<String, Cookie> cookies = new HashMap<String, Cookie>();
		HttpServletResponseWrapper response = spy(new HttpServletResponseWrapper(mock(HttpServletResponse.class)) {
			@Override
			public void addCookie(Cookie cookie) {
				cookies.put(cookie.getName(), cookie);
			}
		});

		// target
		AuthorizationResource testee = spy(new AuthorizationResource(TestTokenCreator.getDomain(), null, null, null, null, null, null));

		// test
		testee.deleteTCCookies(response);
		
		// verify
		verify(response, times(2)).addCookie(any(Cookie.class));
		
		String domain = "."+TestTokenCreator.getDomain().toLowerCase();
		assertTrue(cookies.containsKey("tcjwt"));
		Cookie tcjwt = cookies.get("tcjwt");
		assertEquals(0, tcjwt.getMaxAge());
		assertEquals(domain, tcjwt.getDomain().toLowerCase());

		assertTrue(cookies.containsKey("tcsso"));
		Cookie tcsso = cookies.get("tcsso");
		assertEquals(0, tcsso.getMaxAge());
		assertEquals(domain, tcsso.getDomain().toLowerCase());
	}
	
	@Test
	public void testCreateCookie() {
		
		// testee
		String domain = TestTokenCreator.getDomain();
		AuthorizationResource testee = new AuthorizationResource(domain, null, null, null, null, null, null);

		Integer maxAge = 1;
		String name = "NAME";
		String value = "VALUE";
		Cookie result = testee.createCookie(name, value, maxAge);
		
		assertNotNull(result);
		assertEquals(name, result.getName());
		assertEquals(value, result.getValue());
		assertEquals("."+domain.toLowerCase(), result.getDomain());
		assertEquals(maxAge.intValue(), result.getMaxAge());
	}
}
