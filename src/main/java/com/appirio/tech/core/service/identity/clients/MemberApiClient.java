package com.appirio.tech.core.service.identity.clients;

import com.appirio.clients.BaseClient;
import com.appirio.clients.BaseClientConfiguration;
import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.service.identity.M2mAuthConfiguration;
import com.appirio.tech.core.service.identity.representation.MemberInfo;
import com.appirio.tech.core.service.identity.util.Utils;
import org.eclipse.jetty.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class MemberApiClient extends BaseClient {
    /**
     * The logger for this class
     */
    private final static Logger LOGGER = LoggerFactory.getLogger(MemberApiClient.class);

    private M2mAuthConfiguration m2mAuthConfiguration;

    /**
     * Constructor.
     *
     * @param client the Jersey client
     * @param config the configuration
     * @param m2mAuthConfiguration m2m config
     */
    public MemberApiClient(Client client, BaseClientConfiguration config,
                           M2mAuthConfiguration m2mAuthConfiguration) {
        super(client, config);
        this.m2mAuthConfiguration = m2mAuthConfiguration;
    }

    public List<MemberInfo> getUserInfoList(Set<TCID> userIds) {
        List<MemberInfo> res = new ArrayList<>();
        try  {
            StringBuilder strBuffer = new StringBuilder(this.config.getEndpoint());
            strBuffer.append("?fields=handle,email,userId");
            for (TCID userId: userIds) {
                strBuffer.append("&userIds=");
                strBuffer.append(userId.getId());
            }
            WebTarget target = this.client.target(strBuffer.toString());
            final Invocation.Builder request = target.request(MediaType.APPLICATION_JSON_TYPE);
            String authToken = Utils.generateAuthToken(m2mAuthConfiguration);

            Response response = request.header("Authorization", "Bearer " + authToken).get();
            if (response.getStatusInfo().getStatusCode() != HttpStatus.OK_200) {
                LOGGER.error("Unable to fire the event: {}", response);
            } else {
                res = response.readEntity(new GenericType<List<MemberInfo>>() {});
            }
        } catch (Exception e) {
            LOGGER.error("Error occurs while getting member info: {}", e);
        }
        return res;
    }
}
