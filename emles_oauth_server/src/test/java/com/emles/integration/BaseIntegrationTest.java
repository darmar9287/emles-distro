package com.emles.integration;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.UnsupportedEncodingException;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.json.JsonParser;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.fasterxml.jackson.databind.ObjectMapper;

public abstract class BaseIntegrationTest {

	protected JsonParser jsonParser;

	protected ObjectMapper objectMapper;

	protected MockMvc mvc;

	protected String productAdminClientId = "integration_test_product_admin";

	protected String oauthAdminClientId = "integration_test_oauth_admin";

	protected String resourceAdminClientId = "integration_test_resource_admin";

	protected String password = "user";

	protected String accessToken = "";

	protected String refreshToken = "";

	protected String applicationJsonUtf8 = "application/json;charset=UTF-8";
	
	protected Map<String, Object> getJsonMap(MvcResult result) throws UnsupportedEncodingException {
		String responseString = result.getResponse().getContentAsString();
		return jsonParser.parseMap(responseString);
	}
	
	protected MvcResult performChangePasswordRequest(MultiValueMap<String, String> params, HttpHeaders headers,
			Object newCredentials, int expectedStatus) throws Exception {
		return mvc
			.perform(post("/user/change_password")
					.params(params)
					.headers(headers)
					.content(objectMapper.writeValueAsString(newCredentials))
					.contentType(MediaType.APPLICATION_JSON)
					.accept(applicationJsonUtf8))
			.andExpect(status().is(expectedStatus))
			.andExpect(content().contentType(applicationJsonUtf8))
			.andReturn();
	}

	protected MultiValueMap<String, String> prepareOauthParams(String grantType, String clientId, String userName,
			String password) {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", grantType);
		params.add("client_id", clientId);
		params.add("username", userName);
		params.add("password", password);
		return params;
	}

	protected Map<String, Object> loginAs(String userName, String clientId, String pass, int expectedStatus)
			throws Exception {
		MultiValueMap<String, String> params = prepareOauthParams("password", clientId, userName, pass);

		MvcResult result = mvc
				.perform(post("/oauth/token").params(params).with(httpBasic(clientId, password))
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedStatus))
				.andExpect(content().contentType("application/json;charset=UTF-8")).andReturn();
		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		return responseMap;
	}

	protected Map<String, Object> loginAs(String userName, String clientId, String pass) throws Exception {
		return loginAs(userName, clientId, pass, 200);
	}

	@Autowired
	public final void setObjectMapper(ObjectMapper objectMapper) {
		this.objectMapper = objectMapper;
	}

	@Autowired
	public final void setMockMvc(MockMvc mockMvc) {
		this.mvc = mockMvc;
	}
}
