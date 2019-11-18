package com.emles.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.json.JsonParserFactory;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.emles.EmlesOauthServerApplication;
import com.emles.model.AccountActivationToken;
import com.emles.model.AppUser;
import com.emles.model.Authority;
import com.emles.model.Passwords;
import com.emles.model.UserData;
import com.emles.model.UserPasswords;
import com.emles.repository.AccountActivationTokenRepository;
import com.emles.repository.AppUserRepository;
import com.emles.repository.AuthorityRepository;
import com.emles.utils.Utils;
import com.fasterxml.jackson.core.JsonProcessingException;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.DEFINED_PORT, classes = EmlesOauthServerApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties")
@DirtiesContext(classMode = ClassMode.AFTER_EACH_TEST_METHOD)
public class UserDataIntegrationTest extends BaseIntegrationTest {

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private AppUserRepository userRepository;

	@Autowired
	private AccountActivationTokenRepository accountActivationRepository;

	@Autowired
	private AuthorityRepository authorityRepository;

	@Autowired
	private ApprovalStore approvalStore;

	@Autowired
	private DBPopulator dbPopulator;
	
	private AppUser newUser;

	private String newUserPassword = "h4$h3dPa$$";

	@Before
	public void setUp() {
		newUser = new AppUser();
		newUser.setEmail("newuser@emles.com");
		newUser.setName("newuser");
		newUser.setPassword(newUserPassword);
		newUser.setPasswordConfirmation(newUserPassword);
		newUser.setPhone("600600666");
		jsonParser = JsonParserFactory.getJsonParser();
		dbPopulator.populate();
	}

	@Test
	public void testChangePasswordSuccess() throws Exception {
		AppUser user = userRepository.findByName("product_admin");
		String rawPass = "abcd@@@##AA112";
		String newPass = "abcd@@@##AA1112";
		String newPassConfirmation = "abcd@@@##AA1112";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs(user.getName(), productAdminClientId, rawPass);
		accessToken = (String) loginResponse.get("access_token");
		refreshToken = (String) loginResponse.get("refresh_token");

		UserPasswords newCredentials = createUserPasswords(rawPass, newPass, newPassConfirmation);

		MultiValueMap<String, String> params = prepareOauthParams("password", productAdminClientId, user.getName(),
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = performChangePasswordRequest(params, httpHeaders, newCredentials, 200);
		Map<String, Object> responseMap = getJsonMap(result);

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
		String oldPass = "invalidP@@##AA$$11";
		String newPass = "abcd@@@##AA1112";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs(user.getName(), resourceAdminClientId, rawPass);
		accessToken = (String) loginResponse.get("access_token");

		UserPasswords newCredentials = createUserPasswords(oldPass, newPass, newPass);

		MultiValueMap<String, String> params = prepareOauthParams("password", resourceAdminClientId, user.getName(),
				password);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);

		MvcResult result = performChangePasswordRequest(params, httpHeaders, newCredentials, 422);
		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 1);
		assertTrue(errors.contains(Utils.oldPasswordDoesNotMatch));
		signOut(204, accessToken, resourceAdminClientId);
	}

	@Test
	public void testChangePasswordReturns422WhenPasswordsDoNotMatch() throws Exception {
		AppUser user = userRepository.findByName("oauth_admin");
		String rawPass = "abcd@@@##AA112";
		String newPassword = "abcd@@@##AA1112";
		String newPasswordConfirmation = "abcd@@@##AA111";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs(user.getName(), oauthAdminClientId, rawPass);
		accessToken = (String) loginResponse.get("access_token");

		UserPasswords newCredentials = createUserPasswords(rawPass, newPassword, newPasswordConfirmation);

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, user.getName(),
				password);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);

		MvcResult result = performChangePasswordRequest(params, httpHeaders, newCredentials, 422);
		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 1);
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testChangePasswordReturns422WhenNewPasswordIsInvalid() throws Exception {
		AppUser user = userRepository.findByName("oauth_admin");
		String rawPass = "abcd@@@##AA112";
		String newPassword = "invalid";
		String newPasswordConfirmation = "abcd@@@##AA113";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs(user.getName(), oauthAdminClientId, rawPass);
		accessToken = (String) loginResponse.get("access_token");

		UserPasswords newCredentials = createUserPasswords(rawPass, newPassword, newPasswordConfirmation);

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, user.getName(),
				password);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);

		MvcResult result = performChangePasswordRequest(params, httpHeaders, newCredentials, 422);
		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 2);
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
		assertTrue(errors.contains(Utils.newPasswordInvalidMsg));
		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testChangePasswordReturns422WhenNewPasswordConfirmationIsInvalid() throws Exception {
		AppUser user = userRepository.findByName("oauth_admin");
		String rawPass = "abcd@@@##AA112";
		String newPassword = "abcd@@@##AA111";
		String newPasswordConfirmation = "invalid";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs(user.getName(), oauthAdminClientId, rawPass);
		accessToken = (String) loginResponse.get("access_token");

		UserPasswords newCredentials = createUserPasswords(rawPass, newPassword, newPasswordConfirmation);

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, user.getName(),
				password);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);

		MvcResult result = performChangePasswordRequest(params, httpHeaders, newCredentials, 422);
		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 2);
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
		assertTrue(errors.contains(Utils.newPasswordConfirmationInvalidMsg));
		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testChangePasswordReturns422WhenAllPasswordsAreInvalid() throws Exception {
		AppUser user = userRepository.findByName("oauth_admin");
		String rawPass = "abcd@@@##AA112";
		String oldPassword = "invalid2";
		String newPassword = "abcd@@";
		String newPasswordConfirmation = "invalid";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs(user.getName(), oauthAdminClientId, rawPass);
		accessToken = (String) loginResponse.get("access_token");

		UserPasswords newCredentials = createUserPasswords(oldPassword, newPassword, newPasswordConfirmation);

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, user.getName(),
				password);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);

		MvcResult result = performChangePasswordRequest(params, httpHeaders, newCredentials, 422);
		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 5);
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
		String oldPassword = "invalidP@@##AA$$11";
		String newPassword = "abcd@@@##AA1112";
		String newPasswordConfirmation = "abcd@@@##AA1112";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs(user.getName(), resourceAdminClientId, rawPass);
		accessToken = (String) loginResponse.get("access_token");

		UserPasswords newCredentials = createUserPasswords(oldPassword, newPassword, newPasswordConfirmation);

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, user.getName(),
				password);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer ");

		performChangePasswordRequest(params, httpHeaders, newCredentials, 401);
		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testChangePasswordByAdminSuccess() throws Exception {
		AppUser user = userRepository.findByName("resource_admin");
		long userId = user.getId();
		String rawPass = "abcd@@@##AA112";
		String newPass = "abcd@@@##AA1112";
		String newEmail = "res_admin@test.com";
		String newPhone = "999999999";
		String encodedPass = passwordEncoder.encode(rawPass);
		user.setPassword(encodedPass);
		userRepository.save(user);

		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");
		loginResponse = loginAs("resource_admin", resourceAdminClientId, rawPass);
		String resourceAdminAccessToken = (String) loginResponse.get("access_token");
		UserData resourceAdminUserData = createUserData(newEmail, newPhone);

		sendUpdateUserDataRequestForSignedInUser(resourceAdminUserData, resourceAdminClientId, user.getName(),
				resourceAdminAccessToken, 200);

		Passwords newCredentials = createPasswords(newPass, newPass);

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = performChangePasswordRequestByAdmin(userId, newCredentials, params, httpHeaders, 200);

		String expectedResponseMsg = "User (" + user.getName() + ") password has been changed.";
		Map<String, Object> responseMap = getJsonMap(result);
		assertTrue(responseMap.get("msg").equals(expectedResponseMsg));

		signOut(204, accessToken, oauthAdminClientId);
		signOut(401, resourceAdminAccessToken, resourceAdminClientId);
		loginResponse = loginAs("resource_admin", resourceAdminClientId, newPass, 200);
		resourceAdminAccessToken = (String) loginResponse.get("access_token");
		signOut(204, resourceAdminAccessToken, resourceAdminClientId);
	}

	@Test
	public void testChangePasswordByAdminReturns422WhenUserDoesNotExist() throws Exception {
		long userId = Long.MAX_VALUE;
		String newPass = "abcd@@@##AA1112";

		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		Passwords newCredentials = createPasswords(newPass, newPass);

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = performChangePasswordRequestByAdmin(userId, newCredentials, params, httpHeaders, 422);
		Map<String, Object> responseMap = getJsonMap(result);
		assertTrue(responseMap.get("error").equals(Utils.userDoesNotExistMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataSuccess() throws Exception {
		String userName = "oauth_admin";
		String newEmail = "oauth_test@emles.com";
		String newPhone = "799799799";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = createUserData(newEmail, newPhone);
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 200);

		Map<String, Object> responseMap = getJsonMap(result);
		assertTrue(responseMap.get("msg").equals(Utils.changedUserDataMsg));
		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataReturns422WhenEmailIsInvalid() throws Exception {
		String userName = "oauth_admin";
		String newEmail = "invalid";
		String newPhone = "799799799";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = createUserData(newEmail, newPhone);
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);

		String responseString = result.getResponse().getContentAsString();
		Map<String, Object> responseMap = jsonParser.parseMap(responseString);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 1);
		assertTrue(errors.contains(Utils.invalidEmailAddressMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataReturns422WhenPhoneNumberIsInvalid() throws Exception {
		String userName = "oauth_admin";
		String newEmail = "oauth_test@emles.com";
		String newPhone = "79979979";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = createUserData(newEmail, newPhone);
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);
		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 1);
		assertTrue(errors.contains(Utils.invalidPhoneNumberMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataReturns422WhenAllDataIsInvalid() throws Exception {
		String userName = "oauth_admin";
		String newEmail = "invalid";
		String newPhone = "79979979";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = createUserData(newEmail, newPhone);
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);

		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 2);
		assertTrue(errors.contains(Utils.invalidPhoneNumberMsg));
		assertTrue(errors.contains(Utils.invalidEmailAddressMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataReturns422WhenEmailExists() throws Exception {
		String userName = "oauth_admin";
		String newEmail = "resource_admin@emles.com";
		String newPhone = "799799799";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = createUserData(newEmail, newPhone);
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);

		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 1);
		assertTrue(errors.contains(Utils.emailExistsMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataReturns422WhenPhoneNumberExists() throws Exception {
		String userName = "oauth_admin";
		String newEmail = "oauth_test@emles.com";
		String newPhone = "700799799";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = createUserData(newEmail, newPhone);
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);

		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 1);
		assertTrue(errors.contains(Utils.phoneNumberExistsMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataReturns422WhenAllDataExist() throws Exception {
		String userName = "oauth_admin";
		String newEmail = "resource_admin@emles.com";
		String newPhone = "700799799";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = createUserData(newEmail, newPhone);
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);

		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 2);
		assertTrue(errors.contains(Utils.phoneNumberExistsMsg));
		assertTrue(errors.contains(Utils.emailExistsMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataReturns422WhenEmailExistsAndPhoneIsInvalid() throws Exception {
		String userName = "oauth_admin";
		String newEmail = "resource_admin@emles.com";
		String newPhone = "70079979";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = createUserData(newEmail, newPhone);
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);

		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 2);
		assertTrue(errors.contains(Utils.invalidPhoneNumberMsg));
		assertTrue(errors.contains(Utils.emailExistsMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserDataReturns422WhenEmailIsInvalidAndPhoneExists() throws Exception {
		String userName = "oauth_admin";
		String newEmail = "invalid";
		String newPhone = "700-799-799";
		Map<String, Object> loginResponse = loginAs(userName, oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData newUserData = createUserData(newEmail, newPhone);
		MvcResult result = sendUpdateUserDataRequestForSignedInUser(newUserData, oauthAdminClientId, userName,
				accessToken, 422);

		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 2);
		assertTrue(errors.contains(Utils.phoneNumberExistsMsg));
		assertTrue(errors.contains(Utils.invalidEmailAddressMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testChangeUserDataByAdminReturns422WhenUserDoesNotExist() throws Exception {
		long userId = Long.MAX_VALUE;
		String newEmail = "test@test.com";
		String newPhone = "123456789";

		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData userData = createUserData(newEmail, newPhone);

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = performChangeUserDataByAdmin(userId, userData, params, httpHeaders, 422);

		Map<String, Object> responseMap = getJsonMap(result);
		assertTrue(responseMap.get("error").equals(Utils.userDoesNotExistMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testChangeUserDataByAdminSuccess() throws Exception {
		AppUser resourceAdminUser = userRepository.findByName("resource_admin");
		long userId = resourceAdminUser.getId();
		String newEmail = "test@test.com";
		String newPhone = "123456789";

		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		UserData userData = createUserData(newEmail, newPhone);

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = performChangeUserDataByAdmin(userId, userData, params, httpHeaders, 200);

		Map<String, Object> responseMap = getJsonMap(result);
		assertTrue(responseMap.get("msg").equals(Utils.changedUserDataMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testSignUpSuccess() throws Exception {

		MvcResult result = sendSignUpRequest(newUser, 200);

		Map<String, Object> responseMap = getJsonMap(result);
		assertTrue(responseMap.get("msg").equals(Utils.signUpSuccessMsg));

		AppUser found = userRepository.findByName(newUser.getName());

		assertTrue(found != null);
		assertTrue(found.getEmail().equals(newUser.getEmail()));
		assertTrue(found.getName().equals(newUser.getName()));
		assertTrue(found.getPhone().equals(newUser.getPhone()));
		assertEquals(found.getAuthorities().size(), 1);
		assertTrue(found.getAuthorities().get(0).getAuthority().equals("ROLE_USER"));
		assertFalse(found.isEnabled());

		AccountActivationToken activationToken = accountActivationRepository.findByUser(found);
		assertTrue(activationToken != null);
	}

	@Test
	public void testSignUpReturns422WhenUniquePramsExists() throws Exception {

		newUser.setEmail("oauth_admin@emles.com");
		newUser.setName("oauth_admin");
		newUser.setPhone("700700700");

		MvcResult result = sendSignUpRequest(newUser, 422);

		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 3);
		assertTrue(errors.contains(Utils.userNameExistsMsg));
		assertTrue(errors.contains(Utils.phoneNumberExistsMsg));
		assertTrue(errors.contains(Utils.emailExistsMsg));
	}

	@Test
	public void testSignUpReturns422WhenPasswordsDoNotMatch() throws Exception {
		newUser.setPassword(newUserPassword);
		newUser.setPasswordConfirmation(newUserPassword + "s");
		MvcResult result = sendSignUpRequest(newUser, 422);
		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 1);
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
	}

	@Test
	public void testSignUpReturns422WhenPasswordIsInvalid() throws Exception {
		newUser.setPassword("invalid");
		MvcResult result = sendSignUpRequest(newUser, 422);
		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 2);
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
		assertTrue(errors.contains(Utils.invalidPasswordMsg));
	}

	@Test
	public void testSignUpReturns422WhenPasswordConfirmationIsInvalid() throws Exception {
		newUser.setPasswordConfirmation("invalid");
		MvcResult result = sendSignUpRequest(newUser, 422);
		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 2);
		assertTrue(errors.contains(Utils.passwordsNotEqualMsg));
		assertTrue(errors.contains(Utils.invalidPasswordConfirmationMsg));
	}

	@Test
	public void testSignUpReturns422WhenUsernameIsTooShort() throws Exception {
		newUser.setName("tes");
		MvcResult result = sendSignUpRequest(newUser, 422);
		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 1);
		assertTrue(errors.contains(Utils.userNameRequirementMsg));
	}

	@Test
	public void testSignUpReturns422WhenUsernameIsTooLong() throws Exception {
		newUser.setName(Utils.invalidPasswordConfirmationMsg.replaceAll("\\s", ""));
		MvcResult result = sendSignUpRequest(newUser, 422);
		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 1);
		assertTrue(errors.contains(Utils.userNameRequirementMsg));
	}

	@Test
	public void testSignUpReturns422WhenUsernameContainsForbiddenChars() throws Exception {
		newUser.setName("u$ern$m.,_ ");
		MvcResult result = sendSignUpRequest(newUser, 422);
		Map<String, Object> responseMap = getJsonMap(result);
		@SuppressWarnings("unchecked")
		List<String> errors = (List<String>) responseMap.get("validationErrors");

		assertEquals(errors.size(), 1);
		assertTrue(errors.contains(Utils.userNameRequirementMsg));
	}

	@Test
	public void testCreateUserByAdminSuccess() throws Exception {

		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		Authority productAdminAuthority = authorityRepository.findByAuthority("ROLE_PRODUCT_ADMIN");
		Authority userAuthority = authorityRepository.findByAuthority("ROLE_USER");
		List<Authority> authorities = Arrays.asList(productAdminAuthority, userAuthority);
		newUser.setAuthorities(authorities);

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = performCreateUserByAdmin(params, httpHeaders, 200);

		Map<String, Object> responseMap = getJsonMap(result);
		assertTrue(responseMap.get("msg").equals(Utils.userCreatedSuccessMsg));
		
		AppUser found = userRepository.findByName(newUser.getName());
		List<String> authorityNames = found.getAuthorities().stream().map(Authority::getAuthority)
				.collect(Collectors.toList());

		assertNotNull(found);
		assertTrue(found.getEmail().equals(newUser.getEmail()));
		assertTrue(found.getName().equals(newUser.getName()));
		assertTrue(found.getPhone().equals(newUser.getPhone()));
		assertEquals(found.getAuthorities().size(), 2);
		assertTrue(authorityNames.contains("ROLE_PRODUCT_ADMIN"));
		assertTrue(authorityNames.contains("ROLE_USER"));
		assertTrue(found.isEnabled());

		AccountActivationToken activationToken = accountActivationRepository.findByUser(found);
		assertNull(activationToken);

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testSignUpAndActivationSuccess() throws Exception {
		MvcResult result = sendSignUpRequest(newUser, 200);

		AppUser found = userRepository.findByName(newUser.getName());

		AccountActivationToken activationToken = accountActivationRepository.findByUser(found);
		assertNotNull(activationToken);

		result = performActivateAccount(found.getId(), activationToken.getToken(), 200);

		Map<String, Object> responseMap = getJsonMap(result);
		assertTrue(responseMap.get("msg").equals(Utils.accountActivatedMsg));
	}

	@Test
	public void testSignUpAndActivationReturns422WhenUserIdIsInvalid() throws Exception {
		MvcResult result = sendSignUpRequest(newUser, 200);

		AppUser found = userRepository.findByName(newUser.getName());

		AccountActivationToken activationToken = accountActivationRepository.findByUser(found);
		assertNotNull(activationToken);

		result = performActivateAccount(10000L, activationToken.getToken(), 422);

		Map<String, Object> responseMap = getJsonMap(result);
		assertTrue(responseMap.get("error").equals(Utils.invalidActivationTokenMsg));
	}

	@Test
	public void testSignUpAndActivationReturns422WhenUserTokenIsInvalid() throws Exception {
		MvcResult result = sendSignUpRequest(newUser, 200);

		AppUser found = userRepository.findByName(newUser.getName());

		result = performActivateAccount(found.getId(), "invalid", 422);

		Map<String, Object> responseMap = getJsonMap(result);
		assertTrue(responseMap.get("error").equals(Utils.invalidActivationTokenMsg));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testPaginationOfUsers() throws Exception {
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		int numOfRequests = 3;
		for (int i = 0; i < numOfRequests; i++) {
			MvcResult result = sendGetUsersRequest(i, 200);
			Map<String, Object> responseMap = getJsonMap(result);

			List<Object> users = (List<Object>) responseMap.get("content");
			responseMap = (Map<String, Object>) users.get(0);
			assertTrue(responseMap.get("id") != null);
			assertTrue(responseMap.get("name") != null);
			assertTrue(responseMap.get("userData") != null);
			assertTrue(responseMap.get("passwords") == null);
			assertTrue(responseMap.get("enabled") != null);
			assertTrue(responseMap.get("authorities") == null);
			assertTrue(responseMap.get("password") == null);
			assertTrue(responseMap.get("lastPasswordResetDate") == null);
		}
		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testPaginationOfUsersReturns403WhenSignedInUserIsNotOauthAdmin() throws Exception {
		Map<String, Object> loginResponse = loginAs("resource_admin", resourceAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");
		sendGetUsersRequest(0, 403);
		signOut(204, accessToken, resourceAdminClientId);

		loginResponse = loginAs("product_admin", productAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");
		sendGetUsersRequest(0, 403);
		signOut(204, accessToken, productAdminClientId);
	}

	@Test
	public void testShowMyAccount() throws Exception {
		Map<String, Object> loginResponse = loginAs("resource_admin", resourceAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		MultiValueMap<String, String> params = prepareOauthParams("password", resourceAdminClientId, "resource_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = performShowMyAccount(params, httpHeaders, 200);

		Map<String, Object> responseMap = getJsonMap(result);

		assertNotNull(responseMap.get("id"));
		assertNotNull(responseMap.get("name"));
		assertNotNull(responseMap.get("userData"));
		assertNull(responseMap.get("passwords"));
		assertNotNull(responseMap.get("enabled"));
		assertNull(responseMap.get("authorities"));
		assertNull(responseMap.get("password"));
		assertNull(responseMap.get("last_password_reset_date"));
		signOut(204, accessToken, resourceAdminClientId);
	}

	@Test
	public void testShowUserForAdminSuccess() throws Exception {
		AppUser user = userRepository.findByName("resource_admin");
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = performShowUserData(user.getId(), params, httpHeaders, 200);
		Map<String, Object> responseMap = getJsonMap(result);

		assertNotNull(responseMap.get("id"));
		assertNotNull(responseMap.get("name"));
		assertNotNull(responseMap.get("email"));
		assertNotNull(responseMap.get("phone"));
		assertNull(responseMap.get("passwords"));
		assertNotNull(responseMap.get("enabled"));
		assertNotNull(responseMap.get("authorities"));
		assertNull(responseMap.get("password"));
		assertNull(responseMap.get("lastPasswordResetDate"));
		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testShowUserForAdminReturns404WhenUserIdIsInvalid() throws Exception {
		long userId = Long.MAX_VALUE;
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		performShowUserData(userId, params, httpHeaders, 404);

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserAuthoritySuccess() throws Exception {
		AppUser resourceAdmin = userRepository.findByName("resource_admin");
		Authority productAdminAuthority = authorityRepository.findByAuthority("ROLE_PRODUCT_ADMIN");
		Authority oauthAdminAuthority = authorityRepository.findByAuthority("ROLE_OAUTH_ADMIN");
		List<Long> authorityIds = Arrays.asList(productAdminAuthority, oauthAdminAuthority).stream()
				.map(authority -> authority.getId()).collect(Collectors.toList());

		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		List<String> resourceAdminAuthorities = resourceAdmin.getAuthorities().stream().map(Authority::getAuthority)
				.collect(Collectors.toList());

		assertTrue(resourceAdminAuthorities.contains("ROLE_USER"));
		assertFalse(resourceAdminAuthorities.contains("ROLE_PRODUCT_ADMIN"));
		assertFalse(resourceAdminAuthorities.contains("ROLE_OAUTH_ADMIN"));

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = performChangeUserAuthority(resourceAdmin.getId(), authorityIds, params, httpHeaders, 200);

		Map<String, Object> responseMap = getJsonMap(result);
		resourceAdmin = userRepository.findByName("resource_admin");
		resourceAdminAuthorities = resourceAdmin.getAuthorities().stream().map(Authority::getAuthority)
				.collect(Collectors.toList());
		assertFalse(resourceAdminAuthorities.contains("ROLE_USER"));
		assertTrue(resourceAdminAuthorities.contains("ROLE_PRODUCT_ADMIN"));
		assertTrue(resourceAdminAuthorities.contains("ROLE_OAUTH_ADMIN"));
		assertTrue(responseMap.get("msg").equals(Utils.updateUserDataSuccessMsg));

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testUpdateUserAuthorityReturns404WhenUserIdIsNotFound() throws Exception {
		long invalidUserId = Long.MAX_VALUE;
		List<Long> authorityIds = Arrays.asList(1L, 2L);
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");
		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		performChangeUserAuthority(invalidUserId, authorityIds, params, httpHeaders, 404);

		signOut(204, accessToken, oauthAdminClientId);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testShowAuthorities() throws Exception {
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");
		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = fetchAuthorities(params, httpHeaders, 200);
		String responseString = result.getResponse().getContentAsString();
		List<Object> responseList = jsonParser.parseList(responseString);
		assertEquals(responseList.size(), 3);
		responseList.forEach(authorityObj -> {
			Map<String, Object> authorityMap = (Map<String, Object>) authorityObj;
			Set<String> authorityKeys = authorityMap.keySet();
			assertEquals(authorityKeys.size(), 2);
			assertTrue(authorityKeys.contains("id"));
			assertTrue(authorityKeys.contains("authority"));
		});
	}

	@Test
	public void testShowAuthoritiesShouldReturn403WhenUserIsNotOauthAdmin() throws Exception {
		Map<String, Object> loginResponse = loginAs("resource_admin", resourceAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");
		MultiValueMap<String, String> params = prepareOauthParams("password", resourceAdminClientId, "resource_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		fetchAuthorities(params, httpHeaders, 403);
	}

	@Test
	public void testDeleteMyAccount() throws Exception {
		AppUser user = userRepository.findByName("resource_admin");
		Map<String, Object> loginResponse = loginAs("resource_admin", resourceAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");
		MultiValueMap<String, String> params = prepareOauthParams("password", resourceAdminClientId, "resource_admin",
				password);

		assertNotNull(user);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = performDeleteMyAccount(params, httpHeaders, 200);
		Map<String, Object> responseMap = getJsonMap(result);

		user = userRepository.findByName("resource_admin");
		assertNull(user);
		assertTrue(responseMap.get("msg").equals(Utils.accountRemovedMsg));
		signOut(401, accessToken, resourceAdminClientId);
	}

	@Test
	public void testDeleteAccountByAdminSuccess() throws Exception {
		AppUser user = userRepository.findByName("resource_admin");
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");
		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		assertNotNull(user);
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = performDeleteAccountByAdmin(user.getId(), params, httpHeaders, 200);

		Map<String, Object> responseMap = getJsonMap(result);

		user = userRepository.findByName("resource_admin");
		assertNull(user);
		assertTrue(responseMap.get("msg").equals(Utils.accountRemovedMsg));
		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testDeleteAccountByAdminReturns404WheUserIdIsInvalid() throws Exception {
		long invalidId = Long.MAX_VALUE;
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");
		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		performDeleteAccountByAdmin(invalidId, params, httpHeaders, 404);

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testToggleEnableUserReturns404WheUserIdIsInvalid() throws Exception {
		long invalidId = Long.MAX_VALUE;
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");
		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		performToggleEnableUser(invalidId, params, httpHeaders, 404);

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testToggleEnableUserSuccess() throws Exception {
		AppUser user = userRepository.findByName("resource_admin");
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		loginResponse = loginAs("resource_admin", resourceAdminClientId, password);
		String resourceAdminToken = (String) loginResponse.get("access_token");

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		assertTrue(user.isEnabled());

		MvcResult result = performToggleEnableUser(user.getId(), params, httpHeaders, 200);
		Map<String, Object> responseMap = getJsonMap(result);

		assertTrue(responseMap.get("msg").equals(Utils.userDisabledMsg));
		user = userRepository.findByName("resource_admin");
		assertFalse(user.isEnabled());
		signOut(401, resourceAdminToken, resourceAdminClientId);
		loginAs("resource_admin", resourceAdminClientId, password, 400);

		result = performToggleEnableUser(user.getId(), params, httpHeaders, 200);
		responseMap = getJsonMap(result);
		assertTrue(responseMap.get("msg").equals(Utils.userEnabledMsg));

		user = userRepository.findByName("resource_admin");
		assertTrue(user.isEnabled());

		loginResponse = loginAs("resource_admin", resourceAdminClientId, password, 200);
		resourceAdminToken = (String) loginResponse.get("access_token");
		signOut(204, resourceAdminToken, resourceAdminClientId);
		signOut(204, accessToken, oauthAdminClientId);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testShowMyApprovals() throws Exception {
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");
		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = fetchMyApprovals(params, httpHeaders, 200);

		Map<String, Object> responseMap = getJsonMap(result);
		List<Object> approvalList = (List<Object>) responseMap.get("approvals");
		approvalList.forEach(approval -> {
			Map<String, Object> approvalMap = (Map<String, Object>) approval;
			assertTrue(approvalMap.get("userId").equals("oauth_admin"));
			assertTrue(approvalMap.get("status").equals("APPROVED"));
		});
		signOut(204, accessToken, oauthAdminClientId);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testShowUserApprovals() throws Exception {
		AppUser user = userRepository.findByName("resource_admin");
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");
		MvcResult result = fetchUserApprovals(user.getId(), 200);
		Map<String, Object> responseMap = getJsonMap(result);
		List<Object> approvalList = (List<Object>) responseMap.get("approvals");
		assertTrue(approvalList.isEmpty());

		loginResponse = loginAs("resource_admin", resourceAdminClientId, password);
		String resourceAdminToken = (String) loginResponse.get("access_token");

		result = fetchUserApprovals(user.getId(), 200);
		responseMap = getJsonMap(result);
		approvalList = (List<Object>) responseMap.get("approvals");
		approvalList.forEach(approval -> {
			Map<String, Object> approvalMap = (Map<String, Object>) approval;
			assertTrue(approvalMap.get("userId").equals("resource_admin"));
			assertTrue(approvalMap.get("status").equals("APPROVED"));
		});
		signOut(204, accessToken, oauthAdminClientId);
		signOut(204, resourceAdminToken, resourceAdminClientId);
	}

	@Test
	public void testRevokeMyApproval() throws Exception {
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		List<Approval> approvals = approvalStore.getApprovals("oauth_admin", oauthAdminClientId).stream()
				.filter(approval -> approval.getScope().equals("write")).collect(Collectors.toList());

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = performRevokeMyApproval(params, approvals, httpHeaders, 200);

		Map<String, Object> responseMap = getJsonMap(result);

		assertTrue(responseMap.get("msg").equals(Utils.approvalRevokedMsg));
		signOut(401, accessToken, oauthAdminClientId);
	}

	@Test
	public void testRevokeMyApprovalFailsWhenUserIdIsMalformed() throws Exception {
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		List<Approval> approvals = approvalStore.getApprovals("oauth_admin", oauthAdminClientId).stream()
				.filter(approval -> approval.getScope().equals("write")).collect(Collectors.toList());

		Approval approval = approvals.get(0);
		approval.setUserId("resource_admin");

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		performRevokeMyApproval(params, approvals, httpHeaders, 400);
		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testRevokeApprovalByAdmin() throws Exception {
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		loginResponse = loginAs("resource_admin", resourceAdminClientId, password);
		String resourceAdminToken = (String) loginResponse.get("access_token");

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		List<Approval> approvals = approvalStore.getApprovals("resource_admin", resourceAdminClientId).stream()
				.filter(approval -> approval.getScope().equals("write")).collect(Collectors.toList());

		Approval approval = approvals.get(0);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = performRevokeUserApprovalByAdmin(params, approval, httpHeaders, 200);

		Map<String, Object> responseMap = getJsonMap(result);

		assertTrue(responseMap.get("msg").equals(Utils.approvalRevokedMsg));

		signOut(204, accessToken, oauthAdminClientId);
		signOut(401, resourceAdminToken, resourceAdminClientId);
	}

	@Test
	public void testSignOutUserByAdmin() throws Exception {
		AppUser user = userRepository.findByName("resource_admin");
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		loginResponse = loginAs("resource_admin", resourceAdminClientId, password);
		String resourceAdminToken = (String) loginResponse.get("access_token");

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		MvcResult result = signUserOutByAdmin(user.getId(), params, httpHeaders, 200);

		Map<String, Object> responseMap = getJsonMap(result);

		assertTrue(responseMap.get("msg").equals(Utils.userSignedOutMsg));

		signOut(204, accessToken, oauthAdminClientId);
		signOut(401, resourceAdminToken, resourceAdminClientId);
	}

	@Test
	public void testSignOutUserByAdminReturns404WhenUserIdIsInvalid() throws Exception {
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");

		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin",
				password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		signUserOutByAdmin(Long.MAX_VALUE, params, httpHeaders, 404);

		signOut(204, accessToken, oauthAdminClientId);
	}

	@Test
	public void testShowUserApprovalsReturns404WhenUserIdIsInvalid() throws Exception {
		Map<String, Object> loginResponse = loginAs("oauth_admin", oauthAdminClientId, password);
		accessToken = (String) loginResponse.get("access_token");
		fetchUserApprovals(Long.MAX_VALUE, 404);
		signOut(204, accessToken, oauthAdminClientId);
	}

	private MvcResult fetchUserApprovals(long userId, int expectedStatus) throws Exception {
		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin", password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		return mvc
				.perform(get("/admin/user/user_approvals/" + userId)
						.params(params).headers(httpHeaders)
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedStatus))
				.andReturn();
	}

	private MvcResult sendGetUsersRequest(int page, int expectedStatus) throws Exception {
		MultiValueMap<String, String> params = prepareOauthParams("password", oauthAdminClientId, "oauth_admin", password);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Authorization", "Bearer " + accessToken);
		return mvc
				.perform(get("/admin/user/users/" + (page == 0 ? "" : page))
						.params(params).headers(httpHeaders)
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedStatus))
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
	}

	private MvcResult sendSignUpRequest(AppUser newUser, int expectedStatus) throws Exception, JsonProcessingException {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "password");
		params.add("client_id", oauthAdminClientId);
		params.add("username", "oauth_admin");
		params.add("password", password);

		MvcResult result = mvc
				.perform(post("/user/sign_up").params(params).content(objectMapper.writeValueAsString(newUser))
						.contentType(MediaType.APPLICATION_JSON).accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedStatus))
				.andExpect(content().contentType("application/json;charset=UTF-8")).andReturn();
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

	private void sendRefreshTokenRequest(int expectedStatus, String refreshToken, String clientId) throws Exception {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "refresh_token");
		params.add("client_id", clientId);
		params.add("refresh_token", refreshToken);
		mvc.perform(post("/oauth/token").params(params).with(httpBasic(clientId, password))
				.accept("application/json;charset=UTF-8")).andExpect(status().is(expectedStatus))
				.andExpect(content().contentType("application/json;charset=UTF-8"));
	}

	private UserPasswords createUserPasswords(String rawPass, String newPassword, String newPassConfirmation) {
		UserPasswords newCredentials = new UserPasswords();
		newCredentials.setOldPassword(rawPass);
		newCredentials.setNewPassword(newPassword);
		newCredentials.setNewPasswordConfirmation(newPassConfirmation);
		return newCredentials;
	}

	private Passwords createPasswords(String password, String passwordConfirmation) {
		Passwords newCredentials = new Passwords();
		newCredentials.setPassword(password);
		newCredentials.setPasswordConfirmation(passwordConfirmation);
		return newCredentials;
	}

	private UserData createUserData(String newEmail, String newPhone) {
		UserData resourceAdminUserData = new UserData();
		resourceAdminUserData.setEmail(newEmail);
		resourceAdminUserData.setPhone(newPhone);
		return resourceAdminUserData;
	}

	private MvcResult performChangePasswordRequestByAdmin(long userId, Passwords newCredentials,
			MultiValueMap<String, String> params, HttpHeaders httpHeaders, int expectedStatus) throws Exception {
		return mvc
				.perform(post("/admin/user/change_password/" + userId)
						.params(params)
						.headers(httpHeaders)
						.content(objectMapper.writeValueAsString(newCredentials))
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedStatus))
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
	}

	private MvcResult performChangeUserDataByAdmin(long userId, UserData userData, MultiValueMap<String, String> params,
			HttpHeaders httpHeaders, int expectedState) throws Exception {
		return mvc
				.perform(put("/admin/user/update_account/" + userId)
						.params(params)
						.headers(httpHeaders)
						.content(objectMapper.writeValueAsString(userData))
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedState))
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
	}

	private MvcResult performCreateUserByAdmin(MultiValueMap<String, String> params, HttpHeaders httpHeaders, int expectedState)
			throws Exception {
		return mvc
				.perform(post("/admin/user/create_user")
						.params(params)
						.headers(httpHeaders)
						.content(objectMapper.writeValueAsString(newUser))
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedState))
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
	}

	private MvcResult performActivateAccount(long userId, String activationToken, int expectedState)
			throws Exception {
		return mvc
				.perform(
						post("/user/validate_user_account?id=" + userId + "&token=" + activationToken)
								.content(objectMapper.writeValueAsString(newUser))
								.contentType(MediaType.APPLICATION_JSON)
								.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedState))
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
	}

	private MvcResult performShowMyAccount(MultiValueMap<String, String> params, HttpHeaders httpHeaders, int expectedState)
			throws Exception {
		return mvc
				.perform(get("/user/my_account")
						.params(params)
						.headers(httpHeaders)
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedState))
				.andExpect(content().contentType("application/json;charset=UTF-8"))
				.andReturn();
	}

	private MvcResult performShowUserData(long userId, MultiValueMap<String, String> params, HttpHeaders httpHeaders, int expectedState)
			throws Exception {
		return mvc
				.perform(get("/admin/user/show/" + userId)
						.params(params)
						.headers(httpHeaders)
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedState))
				.andReturn();
	}

	private MvcResult performChangeUserAuthority(long userId, List<Long> authorityIds,
			MultiValueMap<String, String> params, HttpHeaders httpHeaders, int expectedState) throws Exception {
		return mvc
				.perform(put("/admin/user/" + userId + "/update_roles")
						.params(params)
						.headers(httpHeaders)
						.content(objectMapper.writeValueAsString(authorityIds))
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedState))
				.andReturn();
	}

	private MvcResult fetchAuthorities(MultiValueMap<String, String> params, HttpHeaders httpHeaders, int expectedState) throws Exception {
		return mvc
				.perform(get("/authority/list")
						.params(params)
						.headers(httpHeaders)
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedState))
				.andReturn();
	}

	private MvcResult performDeleteMyAccount(MultiValueMap<String, String> params, HttpHeaders httpHeaders, int expectedState)
			throws Exception {
		return mvc
				.perform(delete("/user/my_account/delete")
						.params(params)
						.headers(httpHeaders)
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedState))
				.andReturn();
	}

	private MvcResult performDeleteAccountByAdmin(long userId, MultiValueMap<String, String> params,
			HttpHeaders httpHeaders, int expectedState) throws Exception {
		return mvc
				.perform(delete("/admin/user/delete_account/" + userId)
						.params(params)
						.headers(httpHeaders)
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedState))
				.andReturn();
	}

	private MvcResult performToggleEnableUser(long userId, MultiValueMap<String, String> params, HttpHeaders httpHeaders, int expectedState)
			throws Exception {
		return mvc.perform(put("/admin/user/toggle_enable_user/" + userId)
				.params(params)
				.headers(httpHeaders)
				.contentType(MediaType.APPLICATION_JSON)
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedState))
				.andReturn();
	}

	private MvcResult fetchMyApprovals(MultiValueMap<String, String> params, HttpHeaders httpHeaders, int expectedState) throws Exception {
		return mvc
				.perform(get("/user/my_approvals")
						.params(params)
						.headers(httpHeaders)
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedState))
				.andReturn();
	}

	private MvcResult performRevokeMyApproval(MultiValueMap<String, String> params, List<Approval> approvals,
			HttpHeaders httpHeaders, int expectedState) throws Exception {
		return mvc
				.perform(post("/user/revoke_my_approval")
						.params(params)
						.headers(httpHeaders)
						.content(objectMapper.writeValueAsString(approvals.get(0)))
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedState))
				.andReturn();
	}
	
	private MvcResult performRevokeUserApprovalByAdmin(MultiValueMap<String, String> params, Approval approval,
			HttpHeaders httpHeaders, int expectedState) throws Exception, JsonProcessingException {
		return mvc
				.perform(post("/admin/user/revoke_approval")
				.params(params)
				.headers(httpHeaders)
				.content(objectMapper.writeValueAsString(approval))
				.contentType(MediaType.APPLICATION_JSON)
				.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedState))
				.andReturn();
	}

	private MvcResult signUserOutByAdmin(long userId, MultiValueMap<String, String> params, HttpHeaders httpHeaders, int expectedState)
			throws Exception {
		return mvc
				.perform(post("/admin/user/sign_user_out/" + userId)
						.params(params)
						.headers(httpHeaders)
						.contentType(MediaType.APPLICATION_JSON)
						.accept("application/json;charset=UTF-8"))
				.andExpect(status().is(expectedState))
				.andReturn();
	}
}
