package com.emles.integration;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.emles.EmlesOauthServerApplication;

@RunWith(SpringRunner.class)
@SpringBootTest(
	webEnvironment = WebEnvironment.DEFINED_PORT,
	classes = EmlesOauthServerApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties")
@DirtiesContext(classMode = ClassMode.BEFORE_EACH_TEST_METHOD)
public class LoginIntegrationTest {

	@Autowired
	private MockMvc mvc;
	
	@Autowired
	private JdbcClientDetailsService jdbcClientDetailsService;
	
	@Autowired
	private TokenStore tokenStore;
	
	private ClientDetails clientDetails;
	
	private String productAdminClientId = "integration_test_product_admin";
	
	private String oauthAdminClientId = "integration_test_oauth_admin";
	
	private String resourceAdminClientId = "integration_test_resource_admin";
	
	private String password = "user";
	
	@Before
	public void setUp() {
		clientDetails = jdbcClientDetailsService.loadClientByClientId(productAdminClientId);
	}
	
	@Test
	public void testLoginSuccessful() throws Exception {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", productAdminClientId);
		params.add("username", "product_admin");
		params.add("password", password);
		
		mvc.perform(post("/oauth/token")
				.params(params)
				.with(httpBasic(productAdminClientId, password))
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().isOk())
				.andExpect(content().contentType("application/json;charset=UTF-8"));
	}
}
