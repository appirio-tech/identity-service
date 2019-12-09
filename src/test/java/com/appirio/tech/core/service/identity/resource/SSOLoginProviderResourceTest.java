package com.appirio.tech.core.service.identity.resource;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.service.identity.dao.SSOLoginProviderDAO;
import com.appirio.tech.core.service.identity.representation.SSOLoginProvider;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

/**
 * SSOLoginProviderResourceTest is used to test SSOLoginProviderResource.
 * 
 * @author TCCoder
 * @version 1.0
 *
 */
public class SSOLoginProviderResourceTest {

    /**
     * Test get all providers
     *
     * @throws Exception if any error occurs
     */
    @Test
    public void test_getAllProviders() throws Exception {
        TCID userId = new TCID(123456789L);
        AuthUser authUser = TestUtils.createAdminAuthUserMock(userId);
        
        SSOLoginProviderDAO dao = mock(SSOLoginProviderDAO.class);
        
        List<SSOLoginProvider> providers = new ArrayList<>();
        
        SSOLoginProvider p1 = new SSOLoginProvider();
        p1.setName("name 1");
        p1.setType("type 1");
        p1.setSsoLoginProviderId(1);
        
        SSOLoginProvider p2 = new SSOLoginProvider();
        p2.setName("name 2");
        p2.setType("type 2");
        p2.setSsoLoginProviderId(2);
        
        providers.add(p1);
        providers.add(p2);
        
        when(dao.getAllProviders()).thenReturn(providers);
        
        SSOLoginProviderResource resource = new SSOLoginProviderResource(dao);
        
        ApiResponse response = resource.getAllProviders(authUser, null);
        
        List<SSOLoginProvider> result = (List<SSOLoginProvider>) response.getResult().getContent();
        
        assertEquals("2 items expected", 2, result.size());
        
        assertEquals("The id should be equal", 1, result.get(0).getSsoLoginProviderId());
        assertEquals("The id should be equal", 2, result.get(1).getSsoLoginProviderId());
        
        assertEquals("The name should be equal", "name 1", result.get(0).getName());
        assertEquals("The name should be equal", "name 2", result.get(1).getName());
        
        assertEquals("The type should be equal", "type 1", result.get(0).getType());
        assertEquals("The type should be equal", "type 2", result.get(1).getType());        
    }
}
