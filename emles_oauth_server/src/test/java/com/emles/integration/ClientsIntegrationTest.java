package com.emles.integration;

import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;

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

@RunWith(SpringRunner.class)
@SpringBootTest(
	webEnvironment = WebEnvironment.DEFINED_PORT,
	classes = EmlesOauthServerApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties")
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
public class ClientsIntegrationTest {

	@Autowired
	private MockMvc mvc;
	
	@Autowired
	private JdbcClientDetailsService jdbcClientDetailsService;
	
	private JsonParser jsonParser;
	
	private String productAdminClientId = "integration_test_product_admin";
	
	private String oauthAdminClientId = "integration_test_oauth_admin";
	
	private String resourceAdminClientId = "integration_test_resource_admin";
	
	private String password = "user";
	
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
}