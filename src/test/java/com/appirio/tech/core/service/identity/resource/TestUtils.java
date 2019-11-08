package com.appirio.tech.core.service.identity.resource;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

import java.util.Arrays;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.auth.AuthUser;

/**
 * Util class of helper function for tests.
 * 
 * @author ashel
 */
public class TestUtils {

    /**
     * Create mock administrator auth user.
     * @param userId the user id.
     * @return the auth user created.
     */
    public static AuthUser createAdminAuthUserMock(TCID userId) {
        return createAuthUserMock(userId, new String[]{"administrator"});
    }

    /**
     * Create mock normal auth user.
     * @param userId the user id.
     * @return the auth user created.
     */
    public static AuthUser createNormalAuthUserMock(TCID userId) {
        return createAuthUserMock(userId, null);
    }
    
    /**
     * Create mock auth user.
     * @param userId the user id.
     * @param roles the role for this user.
     * @return the auth user created.
     */
    public static AuthUser createAuthUserMock(TCID userId, String[] roles) {
        AuthUser authUser = spy(new AuthUser());
        doReturn(userId).when(authUser).getUserId();
        if(roles!=null && roles.length>0) {
            doReturn(Arrays.asList(roles)).when(authUser).getRoles();
        }
        return authUser;
    }
}
