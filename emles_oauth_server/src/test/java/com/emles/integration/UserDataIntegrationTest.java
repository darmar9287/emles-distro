package com.emles.integration;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.HashMap;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.emles.EmlesOauthServerApplication;
import com.emles.model.AccountActivationToken;
import com.emles.model.AppUser;
import com.emles.model.Authority;
import com.emles.model.UserData;
import com.emles.model.UserPasswords;
import com.emles.repository.AccountActivationTokenRepository;
import com.emles.repository.AppUserRepository;
import com.emles.repository.AuthorityRepository;
import com.emles.utils.Utils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.DEFINED_PORT, classes = EmlesOauthServerApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties")
@DirtiesContext(classMode = ClassMode.AFTER_EACH_TEST_METHOD)
public class UserDataIntegrationTest {

	private JsonParser jsonParser;

	@Autowired
	private ObjectMapper objectMapper;

	@Autowired
	private MockMvc mvc;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private AppUserRepository userRepository;
	
	@Autowired
	private AccountActivationTokenRepository accountActivationRepository;
	
	@Autowired
	private AuthorityRepository authorityRepository;

	private String productAdminClientId = "integration_test_product_admin";

	private String oauthAdminClientId = "integration_test_oauth_admin";

	private String resourceAdminClientId = "integration_test_resource_admin";

	private String password = "user";

	private String accessToken = "";

	private String refreshToken = "";

	@Before
	public void setUp() {
		jsonParser = JsonParserFactory.getJsonParser();
	}

	private Map<String, Object> loginAs(String userName, String clientId, String pass) throws Exception {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", clientId);
		params.add("username", userName);
		params.add("password", pass);

		MvcResult result = mvc
				.perform(post("/oauth/token").params(params).with(httpBasic(clientId, password))
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().isOk()).andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		return responseMap;
	}

	@Test
	public void testChangePasswordSuccess() throws Exception {
		AppUser user = userRepository.findByName("product_admin");
		String rawPass = "abcd@@@##AA112";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs(user.getName(), productAdminClientId, rawPass);
		accessToken = (String) loginResponse.get("access_token");
		refreshToken = (String) loginResponse.get("refresh_token");
		UserPasswords newCredentials = new UserPasswords();
		newCredentials.setOldPassword(rawPass);
		newCredentials.setNewPassword("abcd@@@##AA1112");
		newCredentials.setNewPasswordConfirmation("abcd@@@##AA1112");

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", productAdminClientId);
		params.add("username", user.getName());
		params.add("password", password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = mvc
				.perform(post("/user/change_password").params(params).headers(httpHeaders)
						.content(objectMapper.writeValueAsString(newCredentials))
						.contentType(MediaType.APPLICATION_JSON).accept("application/json;charset=UTF-8"))
				.andExpect(status().isOk()).andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		Map<String, Object> accessTokenMap = (HashMap<String, Object>) responseMap.get("token");
		String newAccessToken = (String) accessTokenMap.get("access_token");
		String newRefreshToken = (String) accessTokenMap.get("refresh_token");

		assertTrue(responseMap.get("msg").equals(Utils.passwordChangedSuccessMsg));
		assertTrue(newAccessToken != null);
		assertFalse(newAccessToken.equals(accessToken));
		assertTrue(newRefreshToken != null);
		assertFalse(newRefreshToken.equals(refreshToken));

		sendRefreshTokenRequest(400, refreshToken, productAdminClientId);
		signOut(401, accessToken, productAdminClientId);
		sendRefreshTokenRequest(200, newRefreshToken, productAdminClientId);
	}

	@Test
	public void testChangePasswordReturns422WhenOldPasswordIsInvalid() throws Exception {
		AppUser user = userRepository.findByName("resource_admin");
		String rawPass = "abcd@@@##AA112";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs(user.getName(), resourceAdminClientId, rawPass);
		accessToken = (String) loginResponse.get("access_token");

		UserPasswords newCredentials = new UserPasswords();
		newCredentials.setOldPassword("invalidP@@##AA$$11");
		newCredentials.setNewPassword("abcd@@@##AA1112");
		newCredentials.setNewPasswordConfirmation("abcd@@@##AA1112");

		MvcResult result = sendChangePasswordRequest(user, newCredentials, resourceAdminClientId, accessToken, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 1);
		assertTrue(errors.contains(Utils.oldPasswordDoesNotMatch));
		signOut(204, accessToken, resourceAdminClientId);
	}

	@Test
	public void testChangePasswordReturns422WhenPasswordsDoNotMatch() throws Exception {
		AppUser user = userRepository.findByName("oauth_admin");
		String rawPass = "abcd@@@##AA112";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs(user.getName(), oauthAdminClientId, rawPass);
		accessToken = (String) loginResponse.get("access_token");

		UserPasswords newCredentials = new UserPasswords();
		newCredentials.setOldPassword(rawPass);
		newCredentials.setNewPassword("abcd@@@##AA1112");
		newCredentials.setNewPasswordConfirmation("abcd@@@##AA111");

		MvcResult result = sendChangePasswordRequest(user, newCredentials, oauthAdminClientId, accessToken, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 1);
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testChangePasswordReturns422WhenNewPasswordIsInvalid() throws Exception {
		AppUser user = userRepository.findByName("oauth_admin");
		String rawPass = "abcd@@@##AA112";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs(user.getName(), oauthAdminClientId, rawPass);
		accessToken = (String) loginResponse.get("access_token");

		UserPasswords newCredentials = new UserPasswords();
		newCredentials.setOldPassword(rawPass);
		newCredentials.setNewPassword("invalid");
		newCredentials.setNewPasswordConfirmation("abcd@@@##AA111");

		MvcResult result = sendChangePasswordRequest(user, newCredentials, oauthAdminClientId, accessToken, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 2);
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
		assertTrue(errors.contains(Utils.newPasswordInvalidMsg));
		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testChangePasswordReturns422WhenNewPasswordConfirmationIsInvalid() throws Exception {
		AppUser user = userRepository.findByName("oauth_admin");
		String rawPass = "abcd@@@##AA112";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs(user.getName(), oauthAdminClientId, rawPass);
		accessToken = (String) loginResponse.get("access_token");

		UserPasswords newCredentials = new UserPasswords();
		newCredentials.setOldPassword(rawPass);
		newCredentials.setNewPassword("abcd@@@##AA111");
		newCredentials.setNewPasswordConfirmation("invalid");

		MvcResult result = sendChangePasswordRequest(user, newCredentials, oauthAdminClientId, accessToken, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 2);
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
		assertTrue(errors.contains(Utils.newPasswordConfirmationInvalidMsg));
		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testChangePasswordReturns422WhenAllPasswordsAreInvalid() throws Exception {
		AppUser user = userRepository.findByName("oauth_admin");
		String rawPass = "abcd@@@##AA112";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs(user.getName(), oauthAdminClientId, rawPass);
		accessToken = (String) loginResponse.get("access_token");

		UserPasswords newCredentials = new UserPasswords();
		newCredentials.setOldPassword("invalid2");
		newCredentials.setNewPassword("abcd@@");
		newCredentials.setNewPasswordConfirmation("invalid");

		MvcResult result = sendChangePasswordRequest(user, newCredentials, oauthAdminClientId, accessToken, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 5);
		assertTrue(errors.contains(Utils.oldPasswordInvalidMsg));
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
		assertTrue(errors.contains(Utils.newPasswordInvalidMsg));
		assertTrue(errors.contains(Utils.newPasswordConfirmationInvalidMsg));
		assertTrue(errors.contains(Utils.oldPasswordDoesNotMatch));
		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testChangePasswordReturns401WhenUserIsNotAuthenticated() throws Exception {
		AppUser user = userRepository.findByName("resource_admin");
		String rawPass = "abcd@@@##AA112";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs(user.getName(), resourceAdminClientId, rawPass);
		accessToken = (String) loginResponse.get("access_token");

		UserPasswords newCredentials = new UserPasswords();
		newCredentials.setOldPassword("invalidP@@##AA$$11");
		newCredentials.setNewPassword("abcd@@@##AA1112");
		newCredentials.setNewPasswordConfirmation("abcd@@@##AA1112");

		sendChangePasswordRequest(user, newCredentials, resourceAdminClientId, "", 401);
	}

	@Test
	public void testChangePasswordByAdminSuccess() throws Exception {
		AppUser user = userRepository.findByName("resource_admin");
		long userId = user.getId();
		String rawPass = "abcd@@@##AA112";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");
		loginResponse = loginAs("resource_admin", resourceAdminClientId, rawPass);
		String resourceAdminAccessToken = (String) loginResponse.get("access_token");
		UserData resourceAdminUserData = new UserData();
		resourceAdminUserData.setEmail("res_admin@test.com");
		resourceAdminUserData.setPhone("999999999");

		sendUpdateUserDataRequestForSignedInUser(resourceAdminUserData, resourceAdminClientId, user.getName(),
				resourceAdminAccessToken, 200);

		UserPasswords newCredentials = new UserPasswords();
		newCredentials.setOldPassword(rawPass);
		newCredentials.setNewPassword("abcd@@@##AA1112");
		newCredentials.setNewPasswordConfirmation("abcd@@@##AA1112");

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		params.add("username", "oauth_admin");
		params.add("password", password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = mvc
				.perform(post("/user/admin/change_password/" + userId).params(params).headers(httpHeaders)
						.content(objectMapper.writeValueAsString(newCredentials))
						.contentType(MediaType.APPLICATION_JSON).accept("application/json;charset=UTF-8"))
				.andExpect(status().is(200)).andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();

		String expectedResponseMsg = "User (" + user.getName() + ") password has been changed.";
		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("msg").equals(expectedResponseMsg));

		signOut(204, accessToken, oauthAdminClientId);
		signOut(401, resourceAdminAccessToken, resourceAdminClientId);
	}

	@Test
	public void testChangePasswordByAdminReturns422WhenUserDoesNotExist() throws Exception {
		long userId = 2000L;
		String rawPass = "abcd@@@##AA112";

		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserPasswords newCredentials = new UserPasswords();
		newCredentials.setOldPassword(rawPass);
		newCredentials.setNewPassword("abcd@@@##AA1112");
		newCredentials.setNewPasswordConfirmation("abcd@@@##AA1112");

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		params.add("username", "oauth_admin");
		params.add("password", password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = mvc
				.perform(post("/user/admin/change_password/" + userId).params(params).headers(httpHeaders)
						.content(objectMapper.writeValueAsString(newCredentials))
						.contentType(MediaType.APPLICATION_JSON).accept("application/json;charset=UTF-8"))
				.andExpect(status().is(422)).andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("error").equals(Utils.userDoesNotExistMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataSuccess() throws Exception {
		String userName = "oauth_admin";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = new UserData();
		newUserData.setEmail("oauth_test@emles.com");
		newUserData.setPhone("799799799");
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 200);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("msg").equals(Utils.changedUserDataMsg));
	}

	@Test
	public void testUpdateUserDataReturns422WhenEmailIsInvalid() throws Exception {
		String userName = "oauth_admin";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = new UserData();
		newUserData.setEmail("invalid");
		newUserData.setPhone("799799799");
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 1);
		assertTrue(errors.contains(Utils.invalidEmailAddressMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataReturns422WhenPhoneNumberIsInvalid() throws Exception {
		String userName = "oauth_admin";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = new UserData();
		newUserData.setEmail("oauth_test@emles.com");
		newUserData.setPhone("79979979");
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 1);
		assertTrue(errors.contains(Utils.invalidPhoneNumberMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataReturns422WhenAllDataIsInvalid() throws Exception {
		String userName = "oauth_admin";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = new UserData();
		newUserData.setEmail("invalid");
		newUserData.setPhone("79979979");
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 2);
		assertTrue(errors.contains(Utils.invalidPhoneNumberMsg));
		assertTrue(errors.contains(Utils.invalidEmailAddressMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataReturns422WhenEmailExists() throws Exception {
		String userName = "oauth_admin";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = new UserData();
		newUserData.setEmail("resource_admin@emles.com");
		newUserData.setPhone("799799799");
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 1);
		assertTrue(errors.contains(Utils.emailExistsMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataReturns422WhenPhoneNumberExists() throws Exception {
		String userName = "oauth_admin";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = new UserData();
		newUserData.setEmail("oauth_test@emles.com");
		newUserData.setPhone("700799799");
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 1);
		assertTrue(errors.contains(Utils.phoneNumberExistsMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataReturns422WhenAllDataExist() throws Exception {
		String userName = "oauth_admin";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = new UserData();
		newUserData.setEmail("resource_admin@emles.com");
		newUserData.setPhone("700799799");
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 2);
		assertTrue(errors.contains(Utils.phoneNumberExistsMsg));
		assertTrue(errors.contains(Utils.emailExistsMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataReturns422WhenEmailExistsAndPhoneIsInvalid() throws Exception {
		String userName = "oauth_admin";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = new UserData();
		newUserData.setEmail("resource_admin@emles.com");
		newUserData.setPhone("70079979");
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 2);
		assertTrue(errors.contains(Utils.invalidPhoneNumberMsg));
		assertTrue(errors.contains(Utils.emailExistsMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataReturns422WhenEmailIsInvalidAndPhoneExists() throws Exception {
		String userName = "oauth_admin";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = new UserData();
		newUserData.setEmail("invalid");
		newUserData.setPhone("700-799-799");
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 2);
		assertTrue(errors.contains(Utils.phoneNumberExistsMsg));
		assertTrue(errors.contains(Utils.invalidEmailAddressMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testChangeUserDataByAdminReturns422WhenUserDoesNotExist() throws Exception {
		long userId = 2000L;

		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData userData = new UserData();
		userData.setEmail("test@test.com");
		userData.setPhone("123456789");

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		params.add("username", "oauth_admin");
		params.add("password", password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = mvc
				.perform(put("/user/admin/update_account/" + userId).params(params).headers(httpHeaders)
						.content(objectMapper.writeValueAsString(userData)).contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(422)).andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("error").equals(Utils.userDoesNotExistMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testChangeUserDataByAdminSuccess() throws Exception {
		AppUser resourceAdminUser = userRepository.findByName("resource_admin");
		long userId = resourceAdminUser.getId();

		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData userData = new UserData();
		userData.setEmail("test@test.com");
		userData.setPhone("123456789");

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		params.add("username", "oauth_admin");
		params.add("password", password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = mvc
				.perform(put("/user/admin/update_account/" + userId).params(params).headers(httpHeaders)
						.content(objectMapper.writeValueAsString(userData)).contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(200)).andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("msg").equals(Utils.changedUserDataMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}
	
	@Test
	public void testSignUpSuccess() throws Exception {

		String newUserPassword = "h4$h3dPa$$";
		AppUser newUser = new AppUser();
		newUser.setEmail("newuser@emles.com");
		newUser.setName("newuser");
		newUser.setPassword(newUserPassword);
		newUser.setPasswordConfirmation(newUserPassword);
		newUser.setPhone("600600666");
		
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		params.add("username", "oauth_admin");
		params.add("password", password);

		MvcResult result = sendSignUpRequest(newUser, 200);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("msg").equals(Utils.signUpSuccessMsg));
		
		AppUser found = userRepository.findByName(newUser.getName());
		
		assertTrue(found != null);
		assertTrue(found.getEmail().equals(newUser.getEmail()));
		assertTrue(found.getName().equals(newUser.getName()));
		assertTrue(found.getPhone().equals(newUser.getPhone()));
		assertTrue(found.getAuthorities().size() == 1);
		assertTrue(found.getAuthorities().get(0).getAuthority().equals("ROLE_USER"));
		assertFalse(found.isEnabled());
		
		AccountActivationToken activationToken = accountActivationRepository.findByUser(found);
		assertTrue(activationToken != null);
	}
	
	@Test
	public void testSignUpReturns422WhenUniquePramsExists() throws Exception {

		String newUserPassword = "h4$h3dPa$$";
		AppUser newUser = new AppUser();
		newUser.setEmail("oauth_admin@emles.com");
		newUser.setName("oauth_admin");
		newUser.setPassword(newUserPassword);
		newUser.setPasswordConfirmation(newUserPassword);
		newUser.setPhone("700700700");
		
		MvcResult result = sendSignUpRequest(newUser, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 3);
		assertTrue(errors.contains(Utils.userNameExistsMsg));
		assertTrue(errors.contains(Utils.phoneNumberExistsMsg));
		assertTrue(errors.contains(Utils.emailExistsMsg));
	}
	
	@Test
	public void testSignUpReturns422WhenPasswordsDoNotMatch() throws Exception {

		String newUserPassword = "h4$h3dPa$$";
		AppUser newUser = new AppUser();
		newUser.setEmail("test_user@emles.com");
		newUser.setName("test_user");
		newUser.setPassword(newUserPassword);
		newUser.setPasswordConfirmation(newUserPassword + "s");
		newUser.setPhone("700720700");
		
		MvcResult result = sendSignUpRequest(newUser, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 1);
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
	}
	
	@Test
	public void testSignUpReturns422WhenPasswordIsInvalid() throws Exception {

		String newUserPassword = "h4$h3dPa$$";
		AppUser newUser = new AppUser();
		newUser.setEmail("test_user@emles.com");
		newUser.setName("test_user");
		newUser.setPassword("invalid");
		newUser.setPasswordConfirmation(newUserPassword);
		newUser.setPhone("700720700");
		
		MvcResult result = sendSignUpRequest(newUser, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 2);
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
		assertTrue(errors.contains(Utils.invalidPasswordMsg));
	}
	
	@Test
	public void testSignUpReturns422WhenPasswordConfirmationIsInvalid() throws Exception {

		String newUserPassword = "h4$h3dPa$$";
		AppUser newUser = new AppUser();
		newUser.setEmail("test_user@emles.com");
		newUser.setName("test_user");
		newUser.setPassword(newUserPassword);
		newUser.setPasswordConfirmation("invalid");
		newUser.setPhone("700720700");
		
		MvcResult result = sendSignUpRequest(newUser, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 2);
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
		assertTrue(errors.contains(Utils.invalidPasswordConfirmationMsg));
	}
	
	@Test
	public void testSignUpReturns422WhenUsernameIsTooShort() throws Exception {

		String newUserPassword = "h4$h3dPa$$";
		AppUser newUser = new AppUser();
		newUser.setEmail("test_user@emles.com");
		newUser.setName("tes");
		newUser.setPassword(newUserPassword);
		newUser.setPasswordConfirmation(newUserPassword);
		newUser.setPhone("700720700");
		
		MvcResult result = sendSignUpRequest(newUser, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 1);
		assertTrue(errors.contains(Utils.userNameRequirementMsg));
	}
	
	@Test
	public void testSignUpReturns422WhenUsernameIsTooLong() throws Exception {

		String newUserPassword = "h4$h3dPa$$";
		AppUser newUser = new AppUser();
		newUser.setEmail("test_user@emles.com");
		newUser.setName(Utils.invalidPasswordConfirmationMsg.replaceAll("\\s", ""));
		newUser.setPassword(newUserPassword);
		newUser.setPasswordConfirmation(newUserPassword);
		newUser.setPhone("700720700");
		
		MvcResult result = sendSignUpRequest(newUser, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 1);
		assertTrue(errors.contains(Utils.userNameRequirementMsg));
	}
	
	@Test
	public void testSignUpReturns422WhenUsernameContainsForbiddenChars() throws Exception {

		String newUserPassword = "h4$h3dPa$$";
		AppUser newUser = new AppUser();
		newUser.setEmail("test_user@emles.com");
		newUser.setName("u$ern$m.,_ ");
		newUser.setPassword(newUserPassword);
		newUser.setPasswordConfirmation(newUserPassword);
		newUser.setPhone("700720700");
		
		MvcResult result = sendSignUpRequest(newUser, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 1);
		assertTrue(errors.contains(Utils.userNameRequirementMsg));
	}
	
	@Test
	public void testCreateUserByAdminSuccess() throws Exception {

		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");
		
		String newUserPassword = "h4$h3dPa$$";
		Authority productAdminAuthority = authorityRepository.findByAuthority("ROLE_PRODUCT_ADMIN");
		Authority userAuthority = authorityRepository.findByAuthority("ROLE_USER");
		List<Authority> authorities = Arrays.asList(productAdminAuthority, userAuthority);
		AppUser newUser = new AppUser();
		newUser.setEmail("newuser@emles.com");
		newUser.setName("newuser");
		newUser.setPassword(newUserPassword);
		newUser.setPasswordConfirmation(newUserPassword);
		newUser.setPhone("600600666");
		newUser.setAuthorities(authorities);
		
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		params.add("username", "oauth_admin");
		params.add("password", password);
		
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = mvc
				.perform(post("/user/admin/create_user").params(params).headers(httpHeaders)
						.content(objectMapper.writeValueAsString(newUser))
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(200))
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("msg").equals(Utils.userCreatedSuccessMsg));
		
		AppUser found = userRepository.findByName(newUser.getName());
		
		assertTrue(found != null);
		assertTrue(found.getEmail().equals(newUser.getEmail()));
		assertTrue(found.getName().equals(newUser.getName()));
		assertTrue(found.getPhone().equals(newUser.getPhone()));
		assertTrue(found.getAuthorities().size() == 2);
		List<String> authorityNames = found.getAuthorities().stream().map(Authority::getAuthority).collect(Collectors.toList());
		assertTrue(authorityNames.contains("ROLE_PRODUCT_ADMIN"));
		assertTrue(authorityNames.contains("ROLE_USER"));
		assertTrue(found.isEnabled());
		
		AccountActivationToken activationToken = accountActivationRepository.findByUser(found);
		assertTrue(activationToken == null);
		
		signOut(204, accessToken, oauthAdminClientId);
	}

	private MvcResult sendSignUpRequest(AppUser newUser, int expectedStatus) throws Exception, JsonProcessingException {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		params.add("username", "oauth_admin");
		params.add("password", password);

		MvcResult result = mvc
				.perform(post("/user/sign_up").params(params)
						.content(objectMapper.writeValueAsString(newUser))
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedStatus))
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
		return result;
	}

	private MvcResult sendUpdateUserDataRequestForSignedInUser(UserData newUserData, String clientId, String userName,
			String authToken, int expectedStatus) throws Exception, JsonProcessingException {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", clientId);
		params.add("username", userName);
		params.add("password", password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + authToken);
		MvcResult result = mvc
				.perform(put("/user/update_account").params(params).headers(httpHeaders)
						.content(objectMapper.writeValueAsString(newUserData)).contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedStatus))
				.andExpect(content().contentType("application/json;charset=UTF-8")).andReturn();
		return result;
	}

	private MvcResult sendChangePasswordRequest(AppUser user, UserPasswords newCredentials, String clientId,
			String authToken, int expectedStatus) throws Exception, JsonProcessingException {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", clientId);
		params.add("username", user.getName());
		params.add("password", password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + authToken);
		MvcResult result = mvc
				.perform(post("/user/change_password").params(params).headers(httpHeaders)
						.content(objectMapper.writeValueAsString(newCredentials))
						.contentType(MediaType.APPLICATION_JSON).accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedStatus))
				.andExpect(content().contentType("application/json;charset=UTF-8")).andReturn();
		return result;
	}

	private void signOut(int exptectedStatus, String token, String clientId) throws Exception {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", clientId);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + token);
		mvc.perform(delete("/sign_out").params(params).headers(httpHeaders).accept("application/json;charset=UTF-8"))
				.andExpect(status().is(exptectedStatus));
	}

	private void sendRefreshTokenRequest(int expectedStatus, String refreshToken, String clientId) throws Exception {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "refresh_token");
		params.add("client_id", clientId);
		params.add("refresh_token", refreshToken);
		mvc.perform(post("/oauth/token").params(params).with(httpBasic(clientId, password))
				.accept("application/json;charset=UTF-8")).andExpect(status().is(expectedStatus))
				.andExpect(content().contentType("application/json;charset=UTF-8"));
	}
}
