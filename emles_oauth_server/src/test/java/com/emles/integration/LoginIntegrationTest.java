package com.emles.integration;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Collection;
import java.util.List;
import java.util.Map;
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
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
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

@RunWith(SpringRunner.class)
@SpringBootTest(
	webEnvironment = WebEnvironment.DEFINED_PORT,
	classes = EmlesOauthServerApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties")
@DirtiesContext(classMode = ClassMode.AFTER_EACH_TEST_METHOD)
public class LoginIntegrationTest {

	@Autowired
	private MockMvc mvc;
	
	@Autowired
	private JdbcClientDetailsService jdbcClientDetailsService;
	
	@Autowired
    private ApprovalStore approvalStore;
	
	@Autowired
	private TokenStore tokenStore;
	
	@Autowired
	private DBPopulator dbPopulator;
	
	private String productAdminClientId = "integration_test_product_admin";
	
	private String oauthAdminClientId = "integration_test_oauth_admin";
	
	private String resourceAdminClientId = "integration_test_resource_admin";
	
	private String password = "user";
	
	private JsonParser jsonParser;
	
	@Before
	public void setUp() {
		jsonParser = JsonParserFactory.getJsonParser();
		dbPopulator.populate();
	}
	
	@Test
	public void testLoginSuccessful() throws Exception {
		String userName = "product_admin";
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", productAdminClientId);
		params.add("username", userName);
		params.add("password", password);

		mvc.perform(post("/oauth/token")
				.params(params)
				.with(httpBasic(productAdminClientId, password))
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().isOk())
				.andExpect(content().contentType("application/json;charset=UTF-8"));

		List<Approval> approvals = getApprovalsForGivenUserName(userName);
		assertFalse(approvals.isEmpty());
	}
	
	@Test
	public void testAccessAndRefreshTokenExpiration() throws Exception {
		String userName = "resource_admin";
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", resourceAdminClientId);
		params.add("username", userName);
		params.add("password", password);

		MvcResult result = mvc.perform(post("/oauth/token")
				.params(params)
				.with(httpBasic(resourceAdminClientId, password))
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().isOk())
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
		
		List<Approval> approvals = getApprovalsForGivenUserName(userName);
		assertFalse(approvals.isEmpty());
		
		Map<String, Object> responseMap = jsonParser.parseMap(result.getResponse().getContentAsString());
		Thread.sleep(35000L);
		approvals = getApprovalsForGivenUserName(userName);
		assertTrue(approvals.isEmpty());
		
		params.clear();
		
		String refreshToken = (String)responseMap.get("refresh_token");
		String accessToken = (String)responseMap.get("access_token");
		
		params.add("grant_type", "refresh_token");
		params.add("client_id", resourceAdminClientId);
		params.add("refresh_token", refreshToken);
		result = mvc.perform(post("/oauth/token")
				.params(params)
				.with(httpBasic(resourceAdminClientId, password))
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().isOk())
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
		
		responseMap = jsonParser.parseMap(result.getResponse().getContentAsString());
		approvals = getApprovalsForGivenUserName(userName);
		refreshToken = (String)responseMap.get("refresh_token");
		accessToken = (String)responseMap.get("access_token");
		OAuth2RefreshToken oauth2RefreshToken = tokenStore.readRefreshToken(refreshToken);
		OAuth2AccessToken oauth2AccessToken = tokenStore.readAccessToken(accessToken);
		
		assertTrue(oauth2AccessToken != null);
		assertTrue(oauth2RefreshToken != null);
		assertFalse(approvals.isEmpty());
		
		Thread.sleep(65000L);
		approvals = getApprovalsForGivenUserName(userName);
		oauth2RefreshToken = tokenStore.readRefreshToken(refreshToken);
		oauth2AccessToken = tokenStore.readAccessToken(accessToken);
		
		assertTrue(oauth2AccessToken == null);
		assertTrue(oauth2RefreshToken == null);
		assertTrue(approvals.isEmpty());
		
		mvc.perform(post("/oauth/token")
				.params(params)
				.with(httpBasic(resourceAdminClientId, password))
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(400))
				.andExpect(content().contentType("application/json;charset=UTF-8"));
		
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		params.clear();
		params.add("grant_type", "password");
		params.add("client_id", resourceAdminClientId);
		
		mvc.perform(get("/clients/list")
				.params(params)
				.headers(httpHeaders)
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(401))
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
	}
	
	@Test
	public void testLoginFailsWithInvalidUsername() throws Exception {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", productAdminClientId);
		params.add("username", "invalid");
		params.add("password", password);

		mvc.perform(post("/oauth/token")
				.params(params)
				.with(httpBasic(productAdminClientId, password))
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(400))
				.andExpect(content().contentType("application/json;charset=UTF-8"));
	}
	
	@Test
	public void testLoginFailsWithInvalidPassword() throws Exception {
		String userName = "resource_admin";
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", productAdminClientId);
		params.add("username", userName);
		params.add("password", "invalid");

		mvc.perform(post("/oauth/token")
				.params(params)
				.with(httpBasic(productAdminClientId, password))
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(400))
				.andExpect(content().contentType("application/json;charset=UTF-8"));
	}
	
	@Test
	public void testLoginFailsWithInvalidClientId() throws Exception {
		String userName = "resource_admin";
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", "invalid");
		params.add("username", userName);
		params.add("password", password);

		mvc.perform(post("/oauth/token")
				.params(params)
				.with(httpBasic(productAdminClientId, password))
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(401))
				.andExpect(content().contentType("application/json;charset=UTF-8"));
	}
	
	@Test
	public void testLoginFailsWithInvalidOauthPassword() throws Exception {
		String userName = "resource_admin";
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		params.add("username", userName);
		params.add("password", password);

		mvc.perform(post("/oauth/token")
				.params(params)
				.contentType(MediaType.APPLICATION_JSON)
				.with(httpBasic(productAdminClientId, "password"))
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(401));
	}
	
	@Test
	public void testLogoutSuccess() throws Exception {
		String userName = "product_admin";
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", productAdminClientId);
		params.add("username", userName);
		params.add("password", password);

		MvcResult result = mvc.perform(post("/oauth/token")
				.params(params)
				.with(httpBasic(productAdminClientId, password))
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().isOk())
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();

		List<Approval> approvals = getApprovalsForGivenUserName(userName);
		assertFalse(approvals.isEmpty());
		
		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		String accessToken = responseMap.get("access_token").toString();
		String refreshToken = (String)responseMap.get("refresh_token");
		OAuth2RefreshToken oauth2RefreshToken = tokenStore.readRefreshToken(refreshToken);
		OAuth2AccessToken oauth2AccessToken = tokenStore.readAccessToken(accessToken);
		
		assertTrue(oauth2AccessToken != null);
		assertTrue(oauth2RefreshToken != null);
		
		params.clear();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		mvc.perform(delete("/sign_out")
				.params(params)
				.headers(httpHeaders)
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(204));
		
		approvals = getApprovalsForGivenUserName(userName);
		oauth2RefreshToken = tokenStore.readRefreshToken(refreshToken);
		oauth2AccessToken = tokenStore.readAccessToken(accessToken);
		
		assertTrue(oauth2AccessToken == null);
		assertTrue(oauth2RefreshToken == null);
		assertTrue(approvals.isEmpty());
		
		result = mvc.perform(get("/clients/list")
				.params(params)
				.headers(httpHeaders)
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(401))
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
		
		responseString = result.getResponse().getContentAsString();
		responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("error").equals("invalid_token"));
		assertTrue(responseMap.get("error_description").equals("Invalid access token: " + accessToken));
	}
	
	private List<Approval> getApprovalsForGivenUserName(final String userName) {
		return jdbcClientDetailsService.listClientDetails()
                .stream()
                .map(clientDetails -> approvalStore.getApprovals(
                        userName,
                        clientDetails.getClientId()))
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
	}
}
