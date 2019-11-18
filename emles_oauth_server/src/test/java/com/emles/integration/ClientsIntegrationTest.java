package com.emles.integration;

import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.json.JsonParser;
import org.springframework.boot.json.JsonParserFactory;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.emles.EmlesOauthServerApplication;
import com.emles.model.Authority;
import com.fasterxml.jackson.databind.ObjectMapper;

@RunWith(SpringRunner.class)
@SpringBootTest(
	webEnvironment = WebEnvironment.DEFINED_PORT,
	classes = EmlesOauthServerApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties")
@DirtiesContext(classMode = ClassMode.AFTER_EACH_TEST_METHOD)
public class ClientsIntegrationTest {

	@Autowired
	private MockMvc mvc;
	
	@Autowired
	private JdbcClientDetailsService jdbcClientDetailsService;
	
	@Autowired
	private ObjectMapper objectMapper;
	
	@Autowired
	private PasswordEncoder bcryptEncoder;
	
	@Autowired
	private TokenStore tokenStore;
	
	@Autowired
	private DBPopulator dbPopulator;
	
	private JsonParser jsonParser;
	
	private String productAdminClientId = "integration_test_product_admin";
	
	private String oauthAdminClientId = "integration_test_oauth_admin";
	
	private String resourceAdminClientId = "integration_test_resource_admin";
	
	private String password = "user";
	
	private String accessToken = "";
	
	private String loginAs(String userName, String clientId) throws Exception {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", clientId);
		params.add("username", userName);
		params.add("password", password);

		MvcResult result = mvc.perform(post("/oauth/token")
				.params(params)
				.with(httpBasic(clientId, password))
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().isOk())
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		return responseMap.get("access_token").toString();
	}
	
	@Before
	public void setUp() {
		jsonParser = JsonParserFactory.getJsonParser();
		dbPopulator.populate();
	}
	
	@After
	public void tearDown() {
		OAuth2AccessToken oauthAccessToken = tokenStore.readAccessToken(accessToken);
		tokenStore.removeAccessToken(oauthAccessToken);
	}
	
	@Test
	public void testListingOfClientDetails() throws Exception {
		accessToken = loginAs("oauth_admin", oauthAdminClientId);
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = mvc.perform(get("/clients/list")
				.params(params)
				.headers(httpHeaders)
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().isOk())
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
		String responseString = result.getResponse().getContentAsString();
		List<Object> responseMap = jsonParser.parseList(responseString);
		assertTrue(responseMap.size() == 3);
	}
	
	@SuppressWarnings("unchecked")
	@Test
	public void testShowClientDetails() throws Exception {
		accessToken = loginAs("oauth_admin", oauthAdminClientId);
		BaseClientDetails oauthClientDetails = (BaseClientDetails)jdbcClientDetailsService.loadClientByClientId(oauthAdminClientId);
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		
		MvcResult result = mvc.perform(get("/clients/show/" + oauthAdminClientId)
				.params(params)
				.headers(httpHeaders)
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().isOk())
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
		
		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		List<String> scopes = (List<String>)responseMap.get("scope");
		List<String> resourceIds = (List<String>)responseMap.get("resource_ids");
		List<String> authorizedGrantTypes = (List<String>)responseMap.get("authorized_grant_types");
		List<String> registeredRedirectUris = (List<String>)responseMap.get("redirect_uri");
		List<String> autoApproveScopes = (List<String>)responseMap.get("autoapprove");
		List<String> authorities = (List<String>)responseMap.get("authorities");
		
		assertTrue(oauthClientDetails.getClientId().equals(responseMap.get("client_id")));
		assertTrue(oauthClientDetails.getClientSecret().equals(responseMap.get("client_secret")));
		assertTrue(oauthClientDetails.getAccessTokenValiditySeconds().equals(responseMap.get("access_token_validity")));
		assertTrue(oauthClientDetails.getRefreshTokenValiditySeconds().equals(responseMap.get("refresh_token_validity")));
		assertTrue(scopes.equals(oauthClientDetails.getScope().stream().collect(Collectors.toList())));
		assertTrue(resourceIds.equals(oauthClientDetails.getResourceIds().stream().collect(Collectors.toList())));
		assertTrue(authorizedGrantTypes.equals(oauthClientDetails.getAuthorizedGrantTypes().stream().collect(Collectors.toList())));
		assertTrue(registeredRedirectUris.equals(oauthClientDetails.getRegisteredRedirectUri().stream().collect(Collectors.toList())));
		assertTrue(autoApproveScopes.equals(oauthClientDetails.getAutoApproveScopes().stream().collect(Collectors.toList())));
		assertTrue(authorities.equals(oauthClientDetails.getAuthorities().stream().map(GrantedAuthority::toString).collect(Collectors.toList())));
	}
	
	@Test
	public void testShowClientDetailsReturns404ForNotExistingClientId() throws Exception {
		accessToken = loginAs("oauth_admin", oauthAdminClientId);
		String nonExistingClientId = "does_not_exist";
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		
		MvcResult result = mvc.perform(get("/clients/show/" + nonExistingClientId)
				.params(params)
				.headers(httpHeaders)
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(404))
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
		
		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("msg").equals("Invalid client_id"));
	}
	
	@Test
	public void testCreateNewClientSuccess() throws Exception {
		accessToken = loginAs("oauth_admin", oauthAdminClientId);
		String newClientId = "new_client_id";
		
		Authority authority = new Authority();
		authority.setId(3L);
		authority.setAuthority("ROLE_PRODUCT_ADMIN");
		
		BaseClientDetails baseClientDetails = createBaseClientDetails(newClientId, password, authority);
		
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		
		MvcResult result = mvc.perform(post("/clients/create")
				.params(params)
				.content(objectMapper.writeValueAsString(baseClientDetails))
				.contentType(MediaType.APPLICATION_JSON)
				.headers(httpHeaders))
				.andExpect(status().isOk())
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
		
		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("msg").equals("Client has been created"));
		
		compareClientDetails(newClientId, password, baseClientDetails);
	}
	
	@Test
	public void testUpdateExistingClientId() throws Exception {
		accessToken = loginAs("oauth_admin", oauthAdminClientId);
		String newClientId = "new_client_id";
		String newPassword = "hash";
		
		Authority authority = new Authority();
		authority.setId(3L);
		authority.setAuthority("ROLE_PRODUCT_ADMIN");
		
		BaseClientDetails baseClientDetails = createBaseClientDetails(newClientId, password, authority);
		jdbcClientDetailsService.addClientDetails(baseClientDetails);
		
		authority.setAuthority("ROLE_RESOURCE_ADMIN");
		baseClientDetails.setAuthorities(Arrays.asList(authority));
		baseClientDetails.setClientSecret(newPassword);
		baseClientDetails.setScope(Arrays.asList("read"));
		baseClientDetails.setResourceIds(Arrays.asList("resource_server_api"));
		baseClientDetails.setAuthorizedGrantTypes(Arrays.asList("implicit"));
		baseClientDetails.setRegisteredRedirectUri(Arrays.asList("http://localhost:8001").stream().collect(Collectors.toSet()));
		baseClientDetails.setAccessTokenValiditySeconds(7600);
		baseClientDetails.setRefreshTokenValiditySeconds(1000);
		
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		
		MvcResult result = mvc.perform(put("/clients/edit")
				.params(params)
				.content(objectMapper.writeValueAsString(baseClientDetails))
				.contentType(MediaType.APPLICATION_JSON)
				.headers(httpHeaders))
				.andExpect(status().is(200))
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
		
		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("msg").equals("Client has been updated"));
		
		compareClientDetails(newClientId, newPassword, baseClientDetails);
	}
	
	@Test
	public void testUpdateNonExistingClientId() throws Exception {
		accessToken = loginAs("oauth_admin", oauthAdminClientId);
		String newClientId = "new_client_id";
		
		Authority authority = new Authority();
		authority.setId(3L);
		authority.setAuthority("ROLE_PRODUCT_ADMIN");
		
		BaseClientDetails baseClientDetails = createBaseClientDetails(newClientId, password, authority);
		jdbcClientDetailsService.addClientDetails(baseClientDetails);
		
		authority.setAuthority("ROLE_RESOURCE_ADMIN");
		baseClientDetails.setClientId("invalid_non_existing");
		baseClientDetails.setAuthorities(Arrays.asList(authority));
		baseClientDetails.setClientSecret("hash");
		baseClientDetails.setScope(Arrays.asList("read"));
		baseClientDetails.setResourceIds(Arrays.asList("resource_server_api"));
		baseClientDetails.setAuthorizedGrantTypes(Arrays.asList("implicit"));
		baseClientDetails.setRegisteredRedirectUri(Arrays.asList("http://localhost:8001").stream().collect(Collectors.toSet()));
		baseClientDetails.setAccessTokenValiditySeconds(7600);
		baseClientDetails.setRefreshTokenValiditySeconds(1000);
		
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		
		MvcResult result = mvc.perform(put("/clients/edit")
				.params(params)
				.content(objectMapper.writeValueAsString(baseClientDetails))
				.contentType(MediaType.APPLICATION_JSON)
				.headers(httpHeaders))
				.andExpect(status().is(404))
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
		
		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("msg").equals("Invalid client_id"));
	}
	
	@Test(expected = NoSuchClientException.class)
	public void testDeleteClientSuccessful() throws Exception {
		accessToken = loginAs("oauth_admin", oauthAdminClientId);
		String newClientId = "new_client_id";
		
		Authority authority = new Authority();
		authority.setId(3L);
		authority.setAuthority("ROLE_PRODUCT_ADMIN");
		
		BaseClientDetails baseClientDetails = createBaseClientDetails(newClientId, password, authority);
		jdbcClientDetailsService.addClientDetails(baseClientDetails);
		
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		
		mvc.perform(delete("/clients/delete/" + newClientId)
				.params(params)
				.contentType(MediaType.APPLICATION_JSON)
				.headers(httpHeaders))
				.andExpect(status().is(200))
				.andReturn();
		jdbcClientDetailsService.loadClientByClientId(newClientId);
	}
	
	@Test
	public void testDeleteClientUnsuccessful() throws Exception {
		accessToken = loginAs("oauth_admin", oauthAdminClientId);
		String newClientId = "non_existing";
		
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		
		mvc.perform(delete("/clients/delete/" + newClientId)
				.params(params)
				.contentType(MediaType.APPLICATION_JSON)
				.headers(httpHeaders))
				.andExpect(status().is(404))
				.andReturn();
	}
	
	@Test
	public void testIfProductAdminHasNoAccessToShowClientDetailsEndpoint() throws Exception {
		accessToken = loginAs("product_admin", productAdminClientId);
		performShowClientReturns403(productAdminClientId, accessToken);
	}
	
	@Test
	public void testIfResourceAdminHasNoAccessToShowClientDetailsEndpoint() throws Exception {
		accessToken = loginAs("resource_admin", resourceAdminClientId);
		performShowClientReturns403(resourceAdminClientId, accessToken);
	}
	
	@Test
	public void testIfProductAdminHasNoAccessToUpdateClientDetailsEndpoint() throws Exception {
		accessToken = loginAs("product_admin", productAdminClientId);
		performUpdateClientReturns403(productAdminClientId, accessToken);
	}
	
	@Test
	public void testIfResourceAdminHasNoAccessToUpdateClientDetailsEndpoint() throws Exception {
		accessToken = loginAs("resource_admin", resourceAdminClientId);
		performUpdateClientReturns403(resourceAdminClientId, accessToken);
	}
	
	@Test
	public void testIfProductAdminHasNoAccessToCreateClientDetailsEndpoint() throws Exception {
		accessToken = loginAs("product_admin", productAdminClientId);
		performCreateClientReturns403(productAdminClientId, accessToken);
	}
	
	@Test
	public void testIfResourceAdminHasNoAccessToCreateClientDetailsEndpoint() throws Exception {
		accessToken = loginAs("resource_admin", resourceAdminClientId);
		performCreateClientReturns403(resourceAdminClientId, accessToken);
	}
	
	@Test
	public void testIfProductAdminHasNoAccessToDeleteClientDetailsEndpoint() throws Exception {
		accessToken = loginAs("product_admin", productAdminClientId);
		performDeleteClientReturns403(productAdminClientId, accessToken);
	}
	
	@Test
	public void testIfResourceAdminHasNoAccessToDeleteClientDetailsEndpoint() throws Exception {
		accessToken = loginAs("resource_admin", resourceAdminClientId);
		performDeleteClientReturns403(resourceAdminClientId, accessToken);
	}
	
	@Test
	public void testIfProductAdminHasNoAccessToListClientDetailsEndpoint() throws Exception {
		accessToken = loginAs("product_admin", productAdminClientId);
		performListClientsReturns403(productAdminClientId, accessToken);
	}
	
	@Test
	public void testIfResourceAdminHasNoAccessToListClientDetailsEndpoint() throws Exception {
		accessToken = loginAs("resource_admin", resourceAdminClientId);
		performListClientsReturns403(resourceAdminClientId, accessToken);
	}

	private void performShowClientReturns403(String clientId, String accessToken) throws Exception {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", clientId);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		mvc.perform(get("/clients/show/" + clientId)
				.params(params)
				.headers(httpHeaders)
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(403))
				.andExpect(content().contentType("application/json;charset=UTF-8"));
	}
	
	private void performCreateClientReturns403(String clientId, String accessToken) throws Exception {
		String newClientId = "new_client_id";
		
		Authority authority = new Authority();
		authority.setId(3L);
		authority.setAuthority("ROLE_OAUTH_ADMIN");
		
		BaseClientDetails baseClientDetails = createBaseClientDetails(newClientId, password, authority);
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		
		mvc.perform(post("/clients/create")
			.params(params)
			.content(objectMapper.writeValueAsString(baseClientDetails))
			.contentType(MediaType.APPLICATION_JSON)
			.headers(httpHeaders))
			.andExpect(status().is(403))
			.andExpect(content().contentType("application/json;charset=UTF-8"));
	}
	
	private void performUpdateClientReturns403(String clientId, String accessToken) throws Exception {
		String newClientId = "new_client_id";
		
		Authority authority = new Authority();
		authority.setId(3L);
		authority.setAuthority("ROLE_OAUTH_ADMIN");
		
		BaseClientDetails baseClientDetails = createBaseClientDetails(newClientId, password, authority);
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		
		mvc.perform(put("/clients/edit")
			.params(params)
			.content(objectMapper.writeValueAsString(baseClientDetails))
			.contentType(MediaType.APPLICATION_JSON)
			.headers(httpHeaders))
			.andExpect(status().is(403))
			.andExpect(content().contentType("application/json;charset=UTF-8"));
	}
	
	private void performDeleteClientReturns403(String clientId, String accessToken) throws Exception {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", clientId);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		mvc.perform(delete("/clients/delete/" + clientId)
				.params(params)
				.headers(httpHeaders)
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(403))
				.andExpect(content().contentType("application/json;charset=UTF-8"));
	}
	
	private void performListClientsReturns403(String clientId, String accessToken) throws Exception {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", clientId);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		mvc.perform(get("/clients/list")
				.params(params)
				.headers(httpHeaders)
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(403))
				.andExpect(content().contentType("application/json;charset=UTF-8"));
	}
	
	private BaseClientDetails createBaseClientDetails(String clientId, String plainPassword, Authority authority) {
		BaseClientDetails baseClientDetails = new BaseClientDetails();
		baseClientDetails.setClientId(clientId);
		baseClientDetails.setClientSecret(plainPassword);
		baseClientDetails.setScope(Arrays.asList("read", "write"));
		baseClientDetails.setResourceIds(Arrays.asList("oauth_server_api"));
		baseClientDetails.setAuthorizedGrantTypes(Arrays.asList("password"));
		baseClientDetails.setRegisteredRedirectUri(Arrays.asList("http://localhost:8000").stream().collect(Collectors.toSet()));
		baseClientDetails.setAutoApproveScopes(Arrays.asList("true"));
		baseClientDetails.setAuthorities(Arrays.asList(authority));
		baseClientDetails.setAccessTokenValiditySeconds(3600);
		baseClientDetails.setRefreshTokenValiditySeconds(0);
		
		return baseClientDetails;
	}
	
	private void compareClientDetails(String clientId, String plainPassword, BaseClientDetails baseClientDetails) {
		BaseClientDetails newClientDetails = (BaseClientDetails)jdbcClientDetailsService.loadClientByClientId(clientId);
		List<String> newClientDetailsAuthorities = newClientDetails.getAuthorities().stream().map(a -> a.getAuthority()).collect(Collectors.toList());
		List<String> baseClientDetailsAuthorities = baseClientDetails.getAuthorities().stream().map(a -> a.getAuthority()).collect(Collectors.toList());
		String newClientDetailsSecretHash = newClientDetails.getClientSecret();

		assertTrue(newClientDetails.getClientId().equals(baseClientDetails.getClientId()));
		assertTrue(bcryptEncoder.matches(plainPassword, newClientDetailsSecretHash));
		assertTrue(newClientDetails.getScope().equals(baseClientDetails.getScope()));
		assertTrue(newClientDetails.getResourceIds().equals(baseClientDetails.getResourceIds()));
		assertTrue(newClientDetails.getAuthorizedGrantTypes().equals(baseClientDetails.getAuthorizedGrantTypes()));
		assertTrue(newClientDetails.getRegisteredRedirectUri().equals(baseClientDetails.getRegisteredRedirectUri()));
		assertTrue(newClientDetails.getAutoApproveScopes().equals(baseClientDetails.getAutoApproveScopes()));
		assertTrue(newClientDetailsAuthorities.equals(baseClientDetailsAuthorities));
		assertTrue(newClientDetails.getAccessTokenValiditySeconds().equals(baseClientDetails.getAccessTokenValiditySeconds()));
		assertTrue(newClientDetails.getRefreshTokenValiditySeconds().equals(baseClientDetails.getRefreshTokenValiditySeconds()));
	}
}