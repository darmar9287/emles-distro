package com.emles.integration;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
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
public class LoginIntegrationTest {

	@Autowired
	private MockMvc mvc;
	
	@Autowired
	private JdbcClientDetailsService jdbcClientDetailsService;
	
	@Autowired
    private ApprovalStore approvalStore;
	
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
		/************************* GIVEN ************************/
		String userName = "product_admin";
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", productAdminClientId);
		params.add("username", userName);
		params.add("password", password);
		/************************  WHEN  ************************/
		mvc.perform(post("/oauth/token")
				.params(params)
				.with(httpBasic(productAdminClientId, password))
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().isOk())
				.andExpect(content().contentType("application/json;charset=UTF-8"));
		/************************  THEN  ************************/
		List<Approval> approvals = getApprovalsForGivenUserName(userName);
		assertFalse(approvals.isEmpty());
	}
	
	@Test
	public void testIfTokenIsRemovedFromRedisWhenItsExpired() throws Exception {
		/************************* GIVEN ************************/
		String userName = "resource_admin";
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", resourceAdminClientId);
		params.add("username", userName);
		params.add("password", password);
		/************************  WHEN  ************************/
		mvc.perform(post("/oauth/token")
				.params(params)
				.with(httpBasic(resourceAdminClientId, password))
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().isOk())
				.andExpect(content().contentType("application/json;charset=UTF-8"));
		/************************  THEN  ************************/
		List<Approval> approvals = getApprovalsForGivenUserName(userName);
		assertFalse(approvals.isEmpty());
		Thread.sleep(65000L);
		approvals = getApprovalsForGivenUserName(userName);
		assertTrue(approvals.isEmpty());
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
