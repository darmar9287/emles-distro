package com.emles.integration;

import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.time.Period;
import java.util.Date;
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
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.emles.EmlesOauthServerApplication;
import com.emles.model.AppUser;
import com.emles.model.PasswordResetToken;
import com.emles.model.Passwords;
import com.emles.repository.PasswordTokenRepository;
import com.emles.service.UserService;
import com.emles.utils.Utils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.DEFINED_PORT, classes = EmlesOauthServerApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties")
@DirtiesContext(classMode = ClassMode.AFTER_EACH_TEST_METHOD)
public class ForgotPasswordIntegrationTest {

	@Autowired
	private MockMvc mvc;

	@Autowired
	private UserService userService;

	@Autowired
	PasswordTokenRepository passwordTokenRepository;

	@Autowired
	private ObjectMapper objectMapper;
	
	@Autowired
	private DBPopulator dbPopulator;

	private JsonParser jsonParser;

	private String oauthAdminClientId = "integration_test_oauth_admin";

	private String password = "user";

	@Before
	public void setUp() {
		jsonParser = JsonParserFactory.getJsonParser();
		dbPopulator.populate();
	}

	@Test
	public void testForgotPasswordSuccess() throws Exception {
		AppUser user = userService.findByName("oauth_admin");

		requestPasswordResetToken(user);
		PasswordResetToken token = passwordTokenRepository.findByUser(user);
		AppUser tokenUser = token.getUser();

		assertTrue(token != null);
		assertTrue(user.getEmail().equals(tokenUser.getEmail()));
		assertTrue(user.getId().equals(tokenUser.getId()));
	}

	@Test
	public void testForgotPasswordShouldReturn422WhenEmailIsInvalid() throws Exception {

		MvcResult result = mvc
				.perform(post("/user/forgot_password").with(httpBasic(oauthAdminClientId, password))
						.content(objectMapper.writeValueAsString("invalid")).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().is(422)).andReturn();

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("error").equals(Utils.invalidEmailAddressMsg));
	}

	@Test
	public void testChangeForgottenPasswordSuccess() throws Exception {
		AppUser user = userService.findByName("oauth_admin");

		requestPasswordResetToken(user);
		PasswordResetToken token = passwordTokenRepository.findByUser(user);
		Passwords passwords = new Passwords();
		passwords.setPassword("abcd@@@##AA11");
		passwords.setPasswordConfirmation("abcd@@@##AA11");

		MvcResult result = changeForgottenPasswordRequest(token.getToken(), user.getId(), passwords, 200);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("msg").equals(Utils.passwordChangedSuccessMsg));

		token = passwordTokenRepository.findByUser(user);
		assertTrue(token == null);

		String userName = "oauth_admin";
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		params.add("username", userName);
		params.add("password", passwords.getPassword());

		mvc.perform(post("/oauth/token").params(params).with(httpBasic(oauthAdminClientId, password))
				.accept("application/json;charset=UTF-8")).andExpect(status().isOk())
				.andExpect(content().contentType("application/json;charset=UTF-8"));
	}

	@Test
	public void testChangeForgottenPasswordReturns422WhenTokenIsInvalid() throws Exception {
		AppUser user = userService.findByName("oauth_admin");
		String token = "ABCD-EFGH-IJKL";
		String invalidToken = "invalid";
		Passwords passwords = new Passwords();
		passwords.setPassword("abcd@@@##AA11");
		passwords.setPasswordConfirmation("abcd@@@##AA11");
		userService.createPasswordResetTokenForUser(user, token);

		MvcResult result = changeForgottenPasswordRequest(invalidToken, user.getId(), passwords, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("error").equals(Utils.failedToChangeForgottenPassMsg));
	}

	@Test
	public void testChangeForgottenPasswordReturns422WhenUserIdIsInvalid() throws Exception {
		AppUser user = userService.findByName("oauth_admin");
		String token = "ABCD-EFGH-IJKL";
		Passwords passwords = new Passwords();
		passwords.setPassword("abcd@@@##AA11");
		passwords.setPasswordConfirmation("abcd@@@##AA11");
		userService.createPasswordResetTokenForUser(user, token);

		MvcResult result = changeForgottenPasswordRequest(token, Long.MAX_VALUE, passwords, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("error").equals(Utils.failedToChangeForgottenPassMsg));
	}

	@Test
	public void testChangeForgottenPasswordReturns422WhenTokenIsExpired() throws Exception {
		AppUser user = userService.findByName("oauth_admin");
		String token = "ABCD-EFGH-IJKL";
		Passwords passwords = new Passwords();
		passwords.setPassword("abcd@@@##AA11");
		passwords.setPasswordConfirmation("abcd@@@##AA11");
		userService.createPasswordResetTokenForUser(user, token);
		PasswordResetToken resetToken = passwordTokenRepository.findByUser(user);
		resetToken.setExpiryDate(Date.from(Instant.now().minus(Period.ofDays(2))));
		passwordTokenRepository.save(resetToken);

		MvcResult result = changeForgottenPasswordRequest(token, user.getId(), passwords, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("error").equals(Utils.failedToChangeForgottenPassMsg));
	}

	@Test
	public void testChangeForgottenPasswordReturns422WhenPasswordsAreNotEqual() throws Exception {
		AppUser user = userService.findByName("oauth_admin");
		String token = "ABCD-EFGH-IJKL";
		Passwords passwords = new Passwords();
		passwords.setPassword("abcd@@@##AA11");
		passwords.setPasswordConfirmation("abcd@@@##AA1");
		userService.createPasswordResetTokenForUser(user, token);

		MvcResult result = changeForgottenPasswordRequest(token, user.getId(), passwords, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 1);
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
	}

	@Test
	public void testChangeForgottenPasswordReturns422WhenPasswordIsInvalid() throws Exception {
		AppUser user = userService.findByName("oauth_admin");
		String token = "ABCD-EFGH-IJKL";
		Passwords passwords = new Passwords();
		passwords.setPassword("invalid");
		passwords.setPasswordConfirmation("abcd@@@##AA1");
		userService.createPasswordResetTokenForUser(user, token);

		MvcResult result = changeForgottenPasswordRequest(token, user.getId(), passwords, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 2);
		assertTrue(errors.contains(Utils.invalidPasswordMsg));
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
	}

	@Test
	public void testChangeForgottenPasswordReturns422WhenPasswordConfirmationIsInvalid() throws Exception {
		AppUser user = userService.findByName("oauth_admin");
		String token = "ABCD-EFGH-IJKL";
		Passwords passwords = new Passwords();
		passwords.setPassword("abcd@@@##AA1");
		passwords.setPasswordConfirmation("invalid");
		userService.createPasswordResetTokenForUser(user, token);

		MvcResult result = changeForgottenPasswordRequest(token, user.getId(), passwords, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 2);
		assertTrue(errors.contains(Utils.invalidPasswordConfirmationMsg));
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
	}

	@Test
	public void testChangeForgottenPasswordReturns422WhenPasswordsAreInvalid() throws Exception {
		AppUser user = userService.findByName("oauth_admin");
		String token = "ABCD-EFGH-IJKL";
		Passwords passwords = new Passwords();
		passwords.setPassword("notequal");
		passwords.setPasswordConfirmation("invalid");
		userService.createPasswordResetTokenForUser(user, token);

		MvcResult result = changeForgottenPasswordRequest(token, user.getId(), passwords, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertTrue(errors.size() == 3);
		assertTrue(errors.contains(Utils.invalidPasswordConfirmationMsg));
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
		assertTrue(errors.contains(Utils.invalidPasswordMsg));
	}

	private void requestPasswordResetToken(AppUser user)
			throws Exception, JsonProcessingException, UnsupportedEncodingException {
		MvcResult result = mvc.perform(post("/user/forgot_password").with(httpBasic(oauthAdminClientId, password))
				.content(objectMapper.writeValueAsString(user.getEmail())).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().isOk()).andReturn();

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		assertTrue(responseMap.get("msg").equals(Utils.passwordResetTokenCreatedMsg));
	}

	private MvcResult changeForgottenPasswordRequest(String token, long userId, Passwords passwords,
			int exptectedStatus) throws Exception, JsonProcessingException {
		MvcResult result = mvc
				.perform(post("/user/change_forgotten_password?id=" + userId + "&token=" + token)
						.with(httpBasic(oauthAdminClientId, password))
						.content(objectMapper.writeValueAsString(passwords)).contentType(MediaType.APPLICATION_JSON))
				.andExpect(status().is(exptectedStatus)).andReturn();
		return result;
	}
}
