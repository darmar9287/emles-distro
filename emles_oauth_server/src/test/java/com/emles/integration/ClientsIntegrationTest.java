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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

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
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
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
	
	private JsonParser jsonParser;
	
	private String productAdminClientId = "integration_test_product_admin";
	
	private String oauthAdminClientId = "integration_test_oauth_admin";
	
	private String resourceAdminClientId = "integration_test_resource_admin";
	
	private String password = "user";
	
	private String clientSecretHash = "$2a$10$BurTWIy5NTF9GJJH4magz.9Bd4bBurWYG8tmXxeQh1vs7r/wnCFG2";
	
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
	}
	
	@Test
	public void testListingOfClientDetails() throws Exception {
		String accessToken = loginAs("oauth_admin", oauthAdminClientId);
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
		String accessToken = loginAs("oauth_admin", oauthAdminClientId);
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
		String accessToken = loginAs("oauth_admin", oauthAdminClientId);
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
		String accessToken = loginAs("oauth_admin", oauthAdminClientId);
		String newClientId = "new_client_id";
		
		Authority authority = new Authority();
		authority.setId(3L);
		authority.setAuthority("ROLE_PRODUCT_ADMIN");
		
		BaseClientDetails baseClientDetails = createBaseClientDetails(newClientId, authority);
		
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
		
		compareClientDetails(newClientId, baseClientDetails);
	}
	
	@Test
	public void testUpdateExistingClientId() throws Exception {
		String accessToken = loginAs("oauth_admin", oauthAdminClientId);
		String newClientId = "new_client_id";
		
		Authority authority = new Authority();
		authority.setId(3L);
		authority.setAuthority("ROLE_PRODUCT_ADMIN");
		
		BaseClientDetails baseClientDetails = createBaseClientDetails(newClientId, authority);
		jdbcClientDetailsService.addClientDetails(baseClientDetails);
		
		authority.setAuthority("ROLE_RESOURCE_ADMIN");
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
				.andExpect(status().is(200))
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
		
		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("msg").equals("Client has been updated"));
		
		compareClientDetails(newClientId, baseClientDetails);
	}
	
	@Test
	public void testUpdateNonExistingClientId() throws Exception {
		String accessToken = loginAs("oauth_admin", oauthAdminClientId);
		String newClientId = "new_client_id";
		
		Authority authority = new Authority();
		authority.setId(3L);
		authority.setAuthority("ROLE_PRODUCT_ADMIN");
		
		BaseClientDetails baseClientDetails = createBaseClientDetails(newClientId, authority);
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
		String accessToken = loginAs("oauth_admin", oauthAdminClientId);
		String newClientId = "new_client_id";
		
		Authority authority = new Authority();
		authority.setId(3L);
		authority.setAuthority("ROLE_PRODUCT_ADMIN");
		
		BaseClientDetails baseClientDetails = createBaseClientDetails(newClientId, authority);
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
		String accessToken = loginAs("oauth_admin", oauthAdminClientId);
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
	
	private BaseClientDetails createBaseClientDetails(String clientId, Authority authority) {
		BaseClientDetails baseClientDetails = new BaseClientDetails();
		baseClientDetails.setClientId(clientId);
		baseClientDetails.setClientSecret(clientSecretHash);
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
	
	private void compareClientDetails(String clientId, BaseClientDetails baseClientDetails) {
		BaseClientDetails newClientDetails = (BaseClientDetails)jdbcClientDetailsService.loadClientByClientId(clientId);
		List<String> newClientDetailsAuthorities = newClientDetails.getAuthorities().stream().map(a -> a.getAuthority()).collect(Collectors.toList());
		List<String> baseClientDetailsAuthorities = baseClientDetails.getAuthorities().stream().map(a -> a.getAuthority()).collect(Collectors.toList());
		
		assertTrue(newClientDetails.getClientId().equals(baseClientDetails.getClientId()));
		assertTrue(newClientDetails.getClientSecret().equals(baseClientDetails.getClientSecret()));
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