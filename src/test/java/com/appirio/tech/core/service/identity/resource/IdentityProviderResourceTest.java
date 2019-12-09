package com.appirio.tech.core.service.identity.resource;

import com.appirio.tech.core.api.v3.ApiVersion;
import com.appirio.tech.core.api.v3.exception.APIRuntimeException;
import com.appirio.tech.core.api.v3.request.FilterParameter;
import com.appirio.tech.core.api.v3.request.QueryParameter;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.api.v3.response.Result;
import com.appirio.tech.core.service.identity.dao.IdentityProviderDAO;
import com.appirio.tech.core.service.identity.representation.IdentityProvider;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;

import static javax.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static org.junit.Assert.*;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Created by ramakrishnapemmaraju on 12/8/15.
 */
public class IdentityProviderResourceTest {

    private IdentityProvider buildSSOIp() {

        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setName("test");
        identityProvider.setType("sso");
        return identityProvider;
    }

    private IdentityProvider buildSocialIp() {

        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setName("test");
        identityProvider.setType("social");
        return identityProvider;
    }

    private IdentityProvider buildDefaultIp() {

        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setName("ldap");
        identityProvider.setType("default");
        return identityProvider;
    }

    @Test
    public void testFetchProviderInfo_400Error_WhenNoFilterSpecified() throws Exception {
        // parameter
        FilterParameter filter = new FilterParameter(null); // nothing is specified on the filter

        // mock
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        
        HttpServletRequest request = mock(HttpServletRequest.class);
        IdentityProviderDAO dao = mock(IdentityProviderDAO.class);

        // testee
        IdentityProviderResource testee = new IdentityProviderResource(dao);
        
        // test
        try {
            testee.fetchProviderInfo(query, request);
            fail("fetchProviderInfo() should throw APIRuntimeException.");
        } catch (APIRuntimeException e) {
            assertEquals(SC_BAD_REQUEST, e.getHttpStatus());
        }

        verify(dao, never()).getSSOProviderByUserId(anyString());
        verify(dao, never()).getSSOProviderByEmail(anyString());
        verify(dao, never()).getSSOProviderByHandle(anyString());
        verify(dao, never()).getSocialProviderByUserId(anyString());
        verify(dao, never()).getSocialProviderByUserEmail(anyString());
        verify(query).getFilter();
    }

    @Test
    public void testFetchProviderInfo_SSOProviderByUserId() throws Exception{

        // test data
        IdentityProvider ip = buildSSOIp();
        String handle = "test";
        // parameter should be "handle" even if a value is userId in SSO IdP.
        FilterParameter filter = new FilterParameter("handle=" + handle);
        
        // mock
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        HttpServletRequest request = mock(HttpServletRequest.class);
        IdentityProviderDAO dao = mock(IdentityProviderDAO.class);
        when(dao.getSSOProviderByUserId(handle)).thenReturn(ip);

        // testee
        IdentityProviderResource testee = new IdentityProviderResource(dao);
        
        // test
        ApiResponse result = testee.fetchProviderInfo(query, request);

        // check result
        Result apiResult = checkOkResult(result);
        assertEquals(ip, apiResult.getContent());

        verify(dao).getSSOProviderByUserId(handle);
        verify(query).getFilter();
    }

    @Test
    public void testFetchProviderInfo_SSOProviderByEmail() throws Exception{

        // test data
        IdentityProvider ip = buildSSOIp();
        String handle = "test";
        // parameter should be "handle" even if a value is email.
        FilterParameter filter = new FilterParameter("handle=" + handle);
        
        // mock
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        HttpServletRequest request = mock(HttpServletRequest.class);
        IdentityProviderDAO dao = mock(IdentityProviderDAO.class);
        when(dao.getSSOProviderByUserId(handle)).thenReturn(null);
        when(dao.getSSOProviderByEmail(handle)).thenReturn(ip);

        // testee
        IdentityProviderResource testee = new IdentityProviderResource(dao);
        
        // test
        ApiResponse result = testee.fetchProviderInfo(query, request);

        // check result
        Result apiResult = checkOkResult(result);
        assertEquals(ip, apiResult.getContent());

        verify(dao).getSSOProviderByUserId(handle);
        verify(dao).getSSOProviderByEmail(handle);
        verify(query).getFilter();
    }
    
    @Test
    public void testFetchProviderInfo_SSOProviderByHandle() throws Exception{

        // test data
        IdentityProvider ip = buildSSOIp();
        String handle = "test";
        FilterParameter filter = new FilterParameter("handle=" + handle);
        
        // mock
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        HttpServletRequest request = mock(HttpServletRequest.class);
        IdentityProviderDAO dao = mock(IdentityProviderDAO.class);
        when(dao.getSSOProviderByUserId(handle)).thenReturn(null);
        when(dao.getSSOProviderByEmail(handle)).thenReturn(null);
        when(dao.getSSOProviderByHandle(handle)).thenReturn(ip);

        // testee
        IdentityProviderResource testee = new IdentityProviderResource(dao);
        
        // test
        ApiResponse result = testee.fetchProviderInfo(query, request);

        // check result
        Result apiResult = checkOkResult(result);
        assertEquals(ip, apiResult.getContent());

        verify(dao).getSSOProviderByUserId(handle);
        verify(dao).getSSOProviderByEmail(handle);
        verify(dao).getSSOProviderByHandle(handle);
        verify(query).getFilter();
    }
    
    @Test
    public void testFetchProviderInfo_SocialProviderByUserId() throws Exception{
        // test data
        IdentityProvider ip = buildSocialIp();
        String handle = "test";
        FilterParameter filter = new FilterParameter("handle=" + handle.toString());
        
        // mock
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        HttpServletRequest request = mock(HttpServletRequest.class);
        IdentityProviderDAO dao = mock(IdentityProviderDAO.class);
        // no record in SSO table
        when(dao.getSSOProviderByUserId(handle)).thenReturn(null);
        when(dao.getSSOProviderByEmail(handle)).thenReturn(null);
        when(dao.getSSOProviderByHandle(handle)).thenReturn(null);
        // hit in Social table
        when(dao.getSocialProviderByUserId(handle)).thenReturn(ip);

        // testee
        IdentityProviderResource testee = new IdentityProviderResource(dao);
        
        // test
        ApiResponse result = testee.fetchProviderInfo(query, request);

        // check result
        Result apiResult = checkOkResult(result);
        assertEquals(ip, apiResult.getContent());

        verify(dao).getSSOProviderByUserId(handle);
        verify(dao).getSSOProviderByEmail(handle);
        verify(dao).getSSOProviderByHandle(handle);
        verify(dao).getSocialProviderByUserId(handle);
        verify(query).getFilter();
    }

    @Test
    public void testFetchProviderInfo_DefaultProviderByUserId() throws Exception{
        // test data
        IdentityProvider ip = buildDefaultIp();
        String handle = "test";
        FilterParameter filter = new FilterParameter("handle=" + handle.toString());
        
        // mock
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        HttpServletRequest request = mock(HttpServletRequest.class);

        IdentityProviderDAO dao = mock(IdentityProviderDAO.class);
        // no record in SSO table
        when(dao.getSSOProviderByUserId(handle)).thenReturn(null);
        when(dao.getSSOProviderByEmail(handle)).thenReturn(null);
        when(dao.getSSOProviderByHandle(handle)).thenReturn(null);
        // no record in Social table
        when(dao.getSocialProviderByUserId(handle)).thenReturn(null);
        when(dao.getSocialProviderByUserEmail(handle)).thenReturn(null);

        // testee
        IdentityProviderResource testee = new IdentityProviderResource(dao);
        
        // test
        ApiResponse result = testee.fetchProviderInfo(query, request);

        // check result
        Result apiResult = checkOkResult(result);
        IdentityProvider res = (IdentityProvider)apiResult.getContent();
        assertEquals(ip.getName(), res.getName());
        assertEquals(ip.getType(), res.getType());

        verify(dao).getSSOProviderByUserId(handle);
        verify(dao).getSSOProviderByEmail(handle);
        verify(dao).getSSOProviderByHandle(handle);
        verify(dao).getSocialProviderByUserId(handle);
        verify(dao, never()).getSocialProviderByUserEmail(handle); // this is invoked when email is specified. 
        verify(query).getFilter();
    }

    @Test
    public void testFetchProviderInfo_SocialProviderByEmail() throws Exception{
    	// test data
        IdentityProvider ip = buildSocialIp();
        String email = "test@appirio.com";
        FilterParameter filter = new FilterParameter("email=" + email.toString());
        
        // mock
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        HttpServletRequest request = mock(HttpServletRequest.class);
        IdentityProviderDAO dao = mock(IdentityProviderDAO.class);
        when(dao.getSocialProviderByUserEmail(email)).thenReturn(ip);

        // testee
        IdentityProviderResource testee = new IdentityProviderResource(dao);
        
        // test
        ApiResponse result = testee.fetchProviderInfo(query, request);

        // check result
        Result apiResult = checkOkResult(result);
        assertEquals(ip, apiResult.getContent());

        verify(dao).getSocialProviderByUserEmail(anyString());
        verify(query).getFilter();
    }

    @Test
    public void testFetchProviderInfo_DefaultProviderByEmail() throws Exception{
    	// test data
        IdentityProvider ip = buildDefaultIp();
        String email = "test@appirio.com";
        FilterParameter filter = new FilterParameter("email=" + email.toString());
        
        // mock
        QueryParameter query = mock(QueryParameter.class);
        when(query.getFilter()).thenReturn(filter);
        HttpServletRequest request = mock(HttpServletRequest.class);
        IdentityProviderDAO dao = mock(IdentityProviderDAO.class);
        // no record in Social table
        when(dao.getSocialProviderByUserEmail(email)).thenReturn(null);

        // testee
        IdentityProviderResource testee = new IdentityProviderResource(dao);
        
        // test
        ApiResponse result = testee.fetchProviderInfo(query, request);

        // check result
        Result apiResult = checkOkResult(result);
        IdentityProvider res = (IdentityProvider)apiResult.getContent();
        assertEquals(ip.getName(), res.getName());
        assertEquals(ip.getType(), res.getType());

        verify(dao).getSocialProviderByUserEmail(anyString());
        verify(query).getFilter();
    }
    
    protected Result checkOkResult(ApiResponse result) {
        assertNotNull("result should not be null.", result);
        assertNotNull(result.getId());
        assertEquals(ApiVersion.v3, result.getVersion());
        Result apiResult = result.getResult();

        assertNotNull(apiResult);
        assertEquals(SC_OK, (int) apiResult.getStatus());
        assertTrue("apiResult#getSuccess() should be true.", apiResult.getSuccess());
        return apiResult;
    }

}
