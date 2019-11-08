package com.appirio.tech.core.service.identity.resource;

import com.appirio.tech.core.api.v3.TCID;
import com.appirio.tech.core.api.v3.dropwizard.APIApplication;
import com.appirio.tech.core.api.v3.dropwizard.RuntimeExceptionMapper;
import com.appirio.tech.core.api.v3.model.annotation.ApiJacksonAnnotationIntrospector;
import com.appirio.tech.core.api.v3.request.PostPutRequest;
import com.appirio.tech.core.api.v3.request.inject.FieldSelectorProvider;
import com.appirio.tech.core.api.v3.request.inject.QueryParameterProvider;
import com.appirio.tech.core.api.v3.response.ApiResponse;
import com.appirio.tech.core.auth.AuthUser;
import com.appirio.tech.core.auth.LocalAuthProvider;
import com.appirio.tech.core.service.identity.dao.PermissionPolicyDAO;
import com.appirio.tech.core.service.identity.dao.RoleDAO;
import com.appirio.tech.core.service.identity.perms.PermissionsPolicy;
import com.appirio.tech.core.service.identity.perms.Policy;
import com.appirio.tech.core.service.identity.perms.PolicySubject;
import com.appirio.tech.core.service.identity.representation.Role;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ser.impl.SimpleFilterProvider;
import com.fasterxml.jackson.databind.util.ISO8601DateFormat;
import com.google.common.collect.ImmutableList;

import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.testing.junit.ResourceTestRule;

import org.junit.ClassRule;
import org.junit.Test;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PoliciesResourceTest {

	private static final PermissionPolicyDAO mockPolicyDAO = mock(PermissionPolicyDAO.class);
	private static final RoleDAO mockRoleDAO = mock(RoleDAO.class);

	private static final ObjectMapper objectMapper;
	private static final AuthUser authUser;

	static {
		objectMapper = new ObjectMapper();
		objectMapper.setDateFormat(ISO8601DateFormat.getInstance());

		// Register Jackson annotation introspector to add additional
		// annotations for API usage,
		// and register default filter that will ignore additional annotation
		// filters if not present during serialization.
		ApiJacksonAnnotationIntrospector intr = new ApiJacksonAnnotationIntrospector();
		objectMapper.setAnnotationIntrospector(intr);
		SimpleFilterProvider filters = new SimpleFilterProvider();
		filters.setFailOnUnknownId(false);
		objectMapper.setFilters(filters);

		APIApplication.JACKSON_OBJECT_MAPPER = objectMapper;

		authUser = new AuthUser() {
			{
				setUserId(new TCID(1L));
				setRoles(ImmutableList.of("Topcoder User", "Copilot"));
			}
		};
		
		Role r = new Role();
        r.setRoleName("Delegate Policy Loader");
        r.setId(new TCID("7"));
        when(mockRoleDAO.findRoleByName(eq("Delegate Policy Loader"))).thenReturn(r);
	}

	@ClassRule
	public static final ResourceTestRule resourceRule = ResourceTestRule.builder()
							.setMapper(objectMapper)
							.addResource(new PoliciesResource(mockPolicyDAO, mockRoleDAO))
							.addProvider(new AuthValueFactoryProvider.Binder<>(AuthUser.class))
							.addProvider(new RuntimeExceptionMapper())
							.addProvider(new QueryParameterProvider.Binder())
							.addProvider(new FieldSelectorProvider.Binder())
							.addProvider(new AuthDynamicFeature(
							        new LocalAuthProvider.Builder<AuthUser>(authUser).buildAuthFilter()))
							.build();

	
	@Test
	public void testQueryPolicies() throws Exception {
		List<PolicySubject> subjects = new ArrayList<>(3);
		List<PermissionsPolicy> policies = new ArrayList<>(3);
		subjects.add(new PolicySubject(authUser.getUserId().toString(), "user"));
		policies.add(new PermissionsPolicy(authUser.getUserId().toString(), "user", "collaboration", new Policy()));
		authUser.getRoles().forEach(role -> {
			subjects.add(new PolicySubject(role, "role"));
			policies.add(new PermissionsPolicy(role, "role", "collaboration", new Policy()));
		});

		when(mockPolicyDAO.getPolicies(eq(subjects))).thenReturn(policies);

		ApiResponse response = resourceRule.client()
                .target("/policies")
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get(ApiResponse.class);

		assertThat(response.getResult().getSuccess()).isTrue();
		assertThat(response.getResult().getContent()).isNotNull();
		List<PermissionsPolicy> retPolicies = response.getContentResourceList(PermissionsPolicy.class);
		assertThat(retPolicies.size()).isEqualTo(policies.size());
	}

	@Test
	public void testQueryPoliciesWithResource() throws Exception {
		List<PolicySubject> subjects = new ArrayList<>(3);
		List<PermissionsPolicy> policies = new ArrayList<>(3);
		subjects.add(new PolicySubject(authUser.getUserId().toString(), "user"));
		policies.add(new PermissionsPolicy(authUser.getUserId().toString(), "user", "collaboration", new Policy()));
		authUser.getRoles().forEach(role -> {
			subjects.add(new PolicySubject(role, "role"));
			policies.add(new PermissionsPolicy(role, "role", "collaboration", new Policy()));
		});

		when(mockPolicyDAO.getPoliciesForResource(any(), eq("collaboration"))).thenReturn(policies);

		ApiResponse response = resourceRule.client()
                .target("/policies").queryParam("resource", "collaboration")
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get(ApiResponse.class);

		assertThat(response.getResult().getSuccess()).isTrue();
		assertThat(response.getResult().getContent()).isNotNull();
		List<PermissionsPolicy> retPolicies = response.getContentResourceList(PermissionsPolicy.class);
		assertThat(retPolicies.size()).isEqualTo(policies.size());
	}

	@Test
	public void testLoadPolicy() throws Exception {
		PermissionsPolicy policy = new PermissionsPolicy("dummy");
		policy.setId(new TCID("dummy-id"));

		when(mockPolicyDAO.loadPolicy("dummy-id")).thenReturn(policy);

		ApiResponse response = resourceRule.client()
                .target("/policies/dummy-id")
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get(ApiResponse.class);

		assertThat(response.getResult().getSuccess()).isTrue();
		assertThat(response.getResult().getContent()).isNotNull();
		PermissionsPolicy retPolicy = response.getContentResource(PermissionsPolicy.class);
		assertThat(retPolicy.getId()).isEqualTo(policy.getId());
	}

	@Test
	public void testLoadPolicyNotFound() throws Exception {

		when(mockPolicyDAO.loadPolicy("no-id")).thenReturn(null);

		try {
			resourceRule.client()
                .target("/policies/no-id").request(MediaType.APPLICATION_JSON_TYPE)
                .get(ApiResponse.class);
			assertThat(false).isTrue();
		} catch (NotFoundException e) {
			assertThat(e.getResponse().getStatus()).isEqualTo(404);
			ApiResponse response = e.getResponse().readEntity(ApiResponse.class);
			assertThat(response).isNotNull();
			assertThat(response.getResult().getStatus()).isEqualTo(404);
		}
	}

	@Test
	public void testCreatePolicy() throws Exception {

		Policy p = new Policy();
		PermissionsPolicy pol = new PermissionsPolicy("test", "test", "test", p);

		PostPutRequest<PermissionsPolicy> param = new PostPutRequest<PermissionsPolicy>();
		param.setParam(pol);

		PermissionsPolicy polWithId = new PermissionsPolicy("test");
		polWithId.setId(new TCID("pol-id"));

		when(mockPolicyDAO.createPolicy(any(), any())).thenReturn(polWithId);
		when(mockPolicyDAO.checkRole(anyString(), anyString())).thenReturn(true);

		Response resp = resourceRule.client()
				.target("/policies").request(MediaType.APPLICATION_JSON_TYPE)
				.post(Entity.json(param));

		ApiResponse response = resp.readEntity(ApiResponse.class);
		
		assertThat(response.getResult().getSuccess()).isTrue();
		assertThat((String) response.getResult().getContent()).isEqualTo("pol-id");

	}

	@Test
	public void testCreatePolicy_401Error() throws Exception {

		Policy p = new Policy();
		PermissionsPolicy pol = new PermissionsPolicy("test", "test", "test", p);

		PostPutRequest<PermissionsPolicy> param = new PostPutRequest<PermissionsPolicy>();
		param.setParam(pol);

		PermissionsPolicy polWithId = new PermissionsPolicy("test");
		polWithId.setId(new TCID("pol-id"));

		when(mockPolicyDAO.createPolicy(any(), any())).thenReturn(polWithId);
		when(mockPolicyDAO.checkRole(anyString(), anyString())).thenReturn(false);

		try {
			resourceRule.client()
					.target("/policies").request(MediaType.APPLICATION_JSON_TYPE)
					.post(Entity.json(param), ApiResponse.class);
			assertThat(false).isTrue();
		} catch (NotAuthorizedException e) {
			assertThat(e.getResponse().getStatus()).isEqualTo(401);
			ApiResponse response = e.getResponse().readEntity(ApiResponse.class);
			assertThat(response).isNotNull();
			assertThat(response.getResult().getStatus()).isEqualTo(401);
		}
	}


	@Test
	public void testCreatePolicy_400Error() throws Exception {

		PermissionsPolicy pol = new PermissionsPolicy("test");
		PostPutRequest<PermissionsPolicy> param = new PostPutRequest<PermissionsPolicy>();
		param.setParam(pol);

		PermissionsPolicy polWithId = new PermissionsPolicy("test");
		polWithId.setId(new TCID("pol-id"));

		when(mockPolicyDAO.createPolicy(any(), any())).thenReturn(polWithId);
		when(mockPolicyDAO.checkRole(anyString(), anyString())).thenReturn(true);

		try {
			resourceRule.client()
					.target("/policies").request(MediaType.APPLICATION_JSON_TYPE)
					.post(Entity.json(param), ApiResponse.class);
			fail("createPolicy() should throw APIRuntimeException.");
		} catch (BadRequestException e) {
			assertThat(e.getResponse().getStatus()).isEqualTo(400);
			ApiResponse response = e.getResponse().readEntity(ApiResponse.class);
			assertThat(response).isNotNull();
			assertThat(response.getResult().getStatus()).isEqualTo(400);
		}
	}

	@Test
	public void testUpdatePolicy() throws Exception {

		PermissionsPolicy pol = new PermissionsPolicy("test");
		pol.setId(new TCID("pol-update"));
		Policy p = new Policy();
		pol.setPolicy(p);
		PostPutRequest<PermissionsPolicy> param = new PostPutRequest<>();
		param.setParam(pol);

		when(mockPolicyDAO.updatePolicy(any(), any())).thenReturn(pol);
		when(mockPolicyDAO.checkRole(anyString(), anyString())).thenReturn(true);

		Response resp = resourceRule.client()
                .target("/policies/pol-update").request(MediaType.APPLICATION_JSON_TYPE)
                .put(Entity.json(param));

		ApiResponse response = resp.readEntity(ApiResponse.class);
		
		assertThat(response.getResult().getSuccess()).isTrue();

		PermissionsPolicy retPol = response.getContentResource(PermissionsPolicy.class);

		assertThat(retPol.getId()).isEqualTo(pol.getId());
		assertThat(retPol.getResource()).isEqualTo(pol.getResource());
	}

	@Test
	public void testUpdatePolicy_Error401() throws Exception {

		PermissionsPolicy pol = new PermissionsPolicy("test");
		pol.setId(new TCID("pol-update"));
		Policy p = new Policy();
		pol.setPolicy(p);
		PostPutRequest<PermissionsPolicy> param = new PostPutRequest<>();
		param.setParam(pol);

		when(mockPolicyDAO.updatePolicy(any(), any())).thenReturn(pol);
		when(mockPolicyDAO.checkRole(anyString(), anyString())).thenReturn(false);

		try {
			resourceRule.client()
					.target("/policies/pol-update").request(MediaType.APPLICATION_JSON_TYPE)
					.put(Entity.json(param), ApiResponse.class);
			assertThat(false).isTrue();
		} catch (NotAuthorizedException e) {
			assertThat(e.getResponse().getStatus()).isEqualTo(401);
			ApiResponse response = e.getResponse().readEntity(ApiResponse.class);
			assertThat(response).isNotNull();
			assertThat(response.getResult().getStatus()).isEqualTo(401);
		}
	}

	@Test
	public void testUpdatePolicyBadRequest() {
		PermissionsPolicy pol = new PermissionsPolicy( "test");
		pol.setId(new TCID("pol-update"));
		Policy p = new Policy();
		pol.setPolicy(p);
		PostPutRequest<PermissionsPolicy> param = new PostPutRequest<PermissionsPolicy>();
		param.setParam(pol);

		try {
			resourceRule.client()
                .target("/policies/bad-request").request(MediaType.APPLICATION_JSON_TYPE)
                .put(Entity.json(param), ApiResponse.class);
			assertThat(false).isTrue();
		} catch (BadRequestException e) {
			assertThat(e.getResponse().getStatus()).isEqualTo(400);
			ApiResponse response = e.getResponse().readEntity(ApiResponse.class);
			assertThat(response).isNotNull();
			assertThat(response.getResult().getStatus()).isEqualTo(400);
		}
	}
}
