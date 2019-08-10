package com.emles.controller;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.emles.model.AppUser;
import com.emles.model.Passwords;
import com.emles.model.UserData;
import com.emles.model.UserPasswords;
import com.emles.service.UserService;
import com.emles.utils.Utils;

@RestController
@RequestMapping("/user")
public class RegistrationController {

	@Autowired
	private UserService userService;

	/**
	 * tokenStore - used for caching access tokens.
	 */
	@Autowired
	private TokenStore tokenStore;

	@Autowired
	private JdbcClientDetailsService clientDetailsService;

	@Autowired
	private ApprovalStore approvalStore;

	@Resource(name = "oauthServerTokenServices")
	private AuthorizationServerTokenServices tokenServices;

	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	@RequestMapping(value = "/admin/update_account/{userId}", method = RequestMethod.PUT)
	public ResponseEntity<?> updateAccountDataByAdmin(@PathVariable("userId") Long userId,
			@Valid @RequestBody UserData userData, Errors errors) {
		Map<String, Object> responseMap = new HashMap<>();
		Optional<AppUser> userOpt = userService.findById(userId);
		if (userOpt.isPresent()) {
			return changeUserData(userData, errors, userOpt.get());
		}

		responseMap.put("error", Utils.userDoesNotExistMsg);
		return ResponseEntity.unprocessableEntity().body(responseMap);
	}

	@PreAuthorize("hasAnyAuthority('ROLE_OAUTH_ADMIN', 'ROLE_PRODUCT_ADMIN', 'ROLE_RESOURCE_ADMIN')")
	@RequestMapping(value = "/update_account", method = RequestMethod.PUT)
	public ResponseEntity<?> updateAccountData(@Valid @RequestBody UserData userData, Errors errors) {
		AppUser user = userService.findByName(SecurityContextHolder.getContext().getAuthentication().getName());
		return changeUserData(userData, errors, user);
	}

	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	@RequestMapping(value = "/admin/change_password/{userId}", method = RequestMethod.POST)
	public ResponseEntity<?> changePasswordByAdmin(@PathVariable("userId") Long userId,
			@Valid @RequestBody UserPasswords passwords, Errors errors) {
		Map<String, Object> responseMap = new HashMap<>();
		List<String> errorMessages = new ArrayList<>();

		Optional<AppUser> userOpt = userService.findById(userId);
		if (userOpt.isPresent()) {
			AppUser user = userOpt.get();
			validateUserPasswords(passwords, errors, errorMessages, user);

			if (errorMessages.size() > 0) {
				responseMap.put("validationErrors", errorMessages);
				return ResponseEntity.unprocessableEntity().body(responseMap);
			}
			userService.updateUserPassword(user, passwords);

			signOutUserRemotely(user);
			responseMap.put("msg", "User (" + user.getName() + ") password has been changed.");
			return ResponseEntity.ok().body(responseMap);
		}
		responseMap.put("error", Utils.userDoesNotExistMsg);
		return ResponseEntity.unprocessableEntity().body(responseMap);
	}

	@PreAuthorize("hasAnyAuthority('ROLE_OAUTH_ADMIN', 'ROLE_PRODUCT_ADMIN', 'ROLE_RESOURCE_ADMIN')")
	@RequestMapping(value = "/change_password", method = RequestMethod.POST)
	public ResponseEntity<?> changePassword(HttpServletRequest request, @Valid @RequestBody UserPasswords passwords,
			Errors errors) {
		Map<String, Object> responseMap = new HashMap<>();
		List<String> errorMessages = new ArrayList<>();
		AppUser user = userService.findByName(SecurityContextHolder.getContext().getAuthentication().getName());

		validateUserPasswords(passwords, errors, errorMessages, user);

		if (errorMessages.size() > 0) {
			responseMap.put("validationErrors", errorMessages);
			return ResponseEntity.unprocessableEntity().body(responseMap);
		}

		userService.updateUserPassword(user, passwords);
		OAuth2AccessToken accessToken = removeAccessTokens(request);

		accessToken = requestNewAccessToken(request, user, accessToken);
		responseMap.put("msg", Utils.passwordChangedSuccessMsg);
		responseMap.put("token", accessToken);
		return ResponseEntity.ok().body(responseMap);
	}

	@RequestMapping(value = "/forgot_password", method = RequestMethod.POST)
	public ResponseEntity<?> resetPassword(HttpServletRequest request, @RequestBody String email) {
		Map<String, Object> responseMap = new HashMap<>();
		AppUser user = userService.findByEmail(email.replace("\"", ""));
		System.out.println(user);
		if (user == null) {
			responseMap.put("error", Utils.invalidEmailAddressMsg);
			return ResponseEntity.unprocessableEntity().body(responseMap);
		}
		String token = UUID.randomUUID().toString();
		userService.createPasswordResetTokenForUser(user, token);
		// TODO: create mail service
		responseMap.put("msg", Utils.passwordResetTokenCreatedMsg);
		return ResponseEntity.ok().body(responseMap);
	}

	@RequestMapping(value = "/change_forgotten_password", method = RequestMethod.POST)
	public ResponseEntity<?> changeForgottenPassword(@Valid @RequestBody Passwords newPassword, Errors errors,
			@RequestParam("id") long id, @RequestParam("token") String token) {

		String result = userService.validatePasswordResetToken(id, token);
		Optional<AppUser> userOpt = userService.findById(id);
		Map<String, Object> responseMap = new HashMap<>();

		if (result != null || !userOpt.isPresent()) {
			responseMap.put("error", Utils.failedToChangeForgottenPassMsg);
			return ResponseEntity.unprocessableEntity().body(responseMap);
		}

		AppUser user = userOpt.get();
		List<String> errorMessages = new ArrayList<>();
		userService.checkEqualityOfPasswords(newPassword.getPassword(), newPassword.getPasswordConfirmation(),
				errorMessages);
		userService.checkOtherValidationErrors(errors, errorMessages);
		if (errorMessages.size() > 0) {
			responseMap.put("validationErrors", errorMessages);
			return ResponseEntity.unprocessableEntity().body(responseMap);
		}

		userService.updateUserPasswordWithResetToken(user, newPassword, token);
		responseMap.put("msg", Utils.passwordChangedSuccessMsg);
		return ResponseEntity.ok().body(responseMap);
	}

	private void signOutUserRemotely(AppUser user) {
		clientDetailsService.listClientDetails().stream().forEach(clientDetails -> {
			Collection<Approval> approvals = approvalStore.getApprovals(user.getName(), clientDetails.getClientId());
			approvalStore.revokeApprovals(approvals);
			tokenStore.findTokensByClientIdAndUserName(clientDetails.getClientId(), user.getName())
					.forEach(accessToken -> {
						Utils.removeTokens(accessToken, tokenStore);
					});
		});
	}

	private OAuth2AccessToken removeAccessTokens(HttpServletRequest request) {
		String authorization = request.getHeader("Authorization");
		OAuth2AccessToken oauthAccessToken = null;
		if (authorization != null && authorization.contains("Bearer")) {
			String tokenId = authorization.substring("Bearer".length() + 1);
			oauthAccessToken = tokenStore.readAccessToken(tokenId);
			if (oauthAccessToken != null) {
				Utils.removeTokens(oauthAccessToken, tokenStore);
			}
		}
		return oauthAccessToken;
	}

	private ResponseEntity<?> changeUserData(UserData userData, Errors errors, AppUser user) {
		Map<String, Object> responseMap = new HashMap<>();
		List<String> errorMessages = new ArrayList<>();

		userService.validateUniqueValuesForUserData(userData, errorMessages, user);
		userService.checkOtherValidationErrors(errors, errorMessages);

		if (errorMessages.size() > 0) {
			responseMap.put("validationErrors", errorMessages);
			return ResponseEntity.unprocessableEntity().body(responseMap);
		}

		userService.updateUserData(user, userData);
		responseMap.put("msg", Utils.changedUserDataMsg);
		return ResponseEntity.ok().body(responseMap);
	}

	private void validateUserPasswords(UserPasswords passwords, Errors errors, List<String> errorMessages,
			AppUser user) {
		userService.checkIfOldPasswordMatches(user, passwords.getOldPassword(), errorMessages);
		userService.checkEqualityOfPasswords(passwords.getNewPassword(), passwords.getNewPasswordConfirmation(),
				errorMessages);
		userService.checkOtherValidationErrors(errors, errorMessages);
	}

	private OAuth2AccessToken requestNewAccessToken(HttpServletRequest request, AppUser signedIn,
			OAuth2AccessToken accessToken) {
		Map<String, String> authorizationParams = new HashMap<>();
		String clientId = request.getParameter("client_id");

		authorizationParams.put("scope", accessToken.getScope().stream().collect(Collectors.joining(" ")));
		authorizationParams.put("username", signedIn.getName());
		authorizationParams.put("client_id", clientId);
		authorizationParams.put("grant", request.getParameter("grant_type"));

		Set<String> responseType = new HashSet<>();

		OAuth2Request authRequest = new OAuth2Request(authorizationParams, clientId, signedIn.getAuthorities(), true,
				accessToken.getScope(), null, "", responseType, null);
		User userPrincipal = new User(signedIn.getName(), signedIn.getPassword(), signedIn.getAuthorities());
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userPrincipal,
				null, signedIn.getAuthorities());
		OAuth2Authentication authenticationRequest = new OAuth2Authentication(authRequest, authenticationToken);
		authenticationRequest.setAuthenticated(true);
		OAuth2AccessToken newToken = tokenServices.createAccessToken(authenticationRequest);
		return newToken;
	}
}
