package com.emles.controller;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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

import com.emles.model.AppUser;
import com.emles.model.Passwords;
import com.emles.model.UserData;
import com.emles.model.UserPasswords;
import com.emles.service.UserService;
import com.emles.utils.Utils;

/**
 * Abstract class extended by com.emles.controller.UsersController and com.emles.controller.admin.UsersController.
 * @author Dariusz Kulig
 *
 */
public abstract class UserControllerBase {

	/**
	 * PER_PAGE - parameter used for pagination.
	 */
	protected int PER_PAGE;

	/**
	 * userService - service used for maintaining AppUser instances.
	 */
	protected UserService userService;

	/**
	 * tokenStore - used for caching access tokens.
	 */
	protected TokenStore tokenStore;

	/**
	 * clientDetailsService - service used for maintaining ClientDetails instances.
	 */
	protected JdbcClientDetailsService clientDetailsService;

	/**
	 * approvalStore - store containing approvals for signed in users.
	 */
	protected ApprovalStore approvalStore;

	/**
	 * tokenServices - used for managing stored access and refresh tokens.
	 */
	protected AuthorizationServerTokenServices tokenServices;

	/**
	 * Setter for userService.
	 * @param userService - instance of UserService implementation.
	 */
	@Autowired
	public final void setUserService(UserService userService) {
		this.userService = userService;
	}

	/**
	 * Setter for tokenStore.
	 * @param tokenStore - instance of TokenStore implementation.
	 */
	@Autowired
	public final void setTokenStore(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}

	/**
	 * Setter for clientDetailsService.
	 * @param clientDetailsService - instance of JdbcClientDetailsService.
	 */
	@Autowired
	public final void setClientDetailsService(JdbcClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	/**
	 * Setter for approvalStore.
	 * @param approvalStore - ApprovalStore implementation instance.
	 */
	@Autowired
	public final void setApprovalStore(ApprovalStore approvalStore) {
		this.approvalStore = approvalStore;
	}

	/**
	 * Setter for tokenServices.
	 * @param tokenServices - instance of AuthorizationServerTokenServices implementation.
	 */
	@Resource(name = "oauthServerTokenServices")
	public final void setTokenServices(AuthorizationServerTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}

	/**
	 * Setter for PER_PAGE.
	 * @param perPage - number of elements per page.
	 */
	@Value("${config.pagination.per_page}")
	public final void setPerPage(int perPage) {
		this.PER_PAGE = perPage;
	}

	/**
	 * Method used to create new user. It is used in sign up endpoint and create user by admin.
	 * @param user - user data to be stored in db.
	 * @param errors - validation errors.
	 * @param isCreatedByAdmin - boolean flag checking if user is created by admin.
	 * @return Success message when all data will be correct. Otherwise error messages will be returned.
	 */
	protected ResponseEntity<?> signUpNewUser(AppUser user, Errors errors, boolean isCreatedByAdmin) {
		List<String> errorMessages = new ArrayList<>();
		Map<String, Object> responseMap = new HashMap<>();

		userService.validateUniqueValuesForUser(user, errorMessages);
		userService.checkEqualityOfPasswords(user, errorMessages);
		userService.checkOtherValidationErrors(errors, errorMessages);

		if (errorMessages.size() > 0) {
			responseMap.put("validationErrors", errorMessages);
			return ResponseEntity.unprocessableEntity().body(responseMap);
		}
		if (!isCreatedByAdmin) {
			userService.saveNewUserWithStandardRole(user);
			String token = UUID.randomUUID().toString();
			userService.createAccountActivationTokenForUser(user, token);
			responseMap.put("msg", Utils.signUpSuccessMsg);
		}
		else {
			userService.createUser(user);
			responseMap.put("msg", Utils.userCreatedSuccessMsg);
		}

		// TODO: create mail service

		return ResponseEntity.ok().body(responseMap);
	}

	/**
	 * Method used for access and refresh token revocation. Also all user approvals will be removed.
	 * @param user - user instance who's going to be signed out from page.
	 */
	protected void signOutUserRemotely(AppUser user) {
		clientDetailsService.listClientDetails().stream().forEach(clientDetails -> {
			Collection<Approval> approvals = approvalStore.getApprovals(user.getName(), clientDetails.getClientId());
			approvalStore.revokeApprovals(approvals);
			tokenStore.findTokensByClientIdAndUserName(clientDetails.getClientId(), user.getName())
					.forEach(accessToken -> {
						Utils.removeTokens(accessToken, tokenStore);
					});
		});
	}

	/**
	 * Method used to remove access and refresh tokens sent in http headers.
	 * @param request - http servlet instance object with http headers containing access token.
	 * @return - oauth access token which should be revoked.
	 */
	protected OAuth2AccessToken removeAccessTokens(HttpServletRequest request) {
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

	/**
	 * Method used to change user data.
	 * @param userData - user data to be updated.
	 * @param errors - validation errors.
	 * @param user - user instance to which changes will be applied.
	 * @return - JSON object containing error messages when data will be incorrect. Otherwise success message will be
	 * sent.
	 */
	protected ResponseEntity<?> changeUserData(UserData userData, Errors errors, AppUser user) {
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

	/**
	 * Method used for validation user passwords.
	 * @param passwords - object containing passwords to be validated.
	 * @param errors - validation errors.
	 * @param errorMessages - list of validation errors.
	 * @param user - user instance who's password should be changed.
	 */
	protected void validateUserPasswords(UserPasswords passwords, Errors errors, List<String> errorMessages,
			AppUser user) {
		userService.checkIfOldPasswordMatches(user, passwords.getOldPassword(), errorMessages);
		userService.checkEqualityOfPasswords(passwords.getNewPassword(), passwords.getNewPasswordConfirmation(),
				errorMessages);
		userService.checkOtherValidationErrors(errors, errorMessages);
	}

	/**
	 * Method used for validation user passwords. Withoud check if password matches in hash stored in db.
	 * @param passwords - object containing passwords to be validated.
	 * @param errors - validation errors.
	 * @param errorMessages - list of validation errors.
	 */
	protected void validateUserPasswords(Passwords passwords, Errors errors, List<String> errorMessages) {
		userService.checkEqualityOfPasswords(passwords.getPassword(), passwords.getPasswordConfirmation(),
				errorMessages);
		userService.checkOtherValidationErrors(errors, errorMessages);
	}

	/**
	 * Method used for requesting new access token.
	 * @param request - http servlet request containing headers with access token.
	 * @param signedIn - instance of user who's access token will be renewed.
	 * @param accessToken - old access token instance.
	 * @return - instance of new access token.
	 */
	protected OAuth2AccessToken requestNewAccessToken(HttpServletRequest request, AppUser signedIn,
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

	/**
	 * Method used for retrieving user approvals.
	 * @param responseMap - map to which approval list will be stored.
	 * @param user - user which approvals will be fetched.
	 */
	protected void fetchApprovalList(Map<String, Object> responseMap, AppUser user) {
		List<Approval> approvals = clientDetailsService.listClientDetails().stream()
				.map(clientDetails -> approvalStore.getApprovals(user.getName(), clientDetails.getClientId()))
				.flatMap(Collection::stream).collect(Collectors.toList());
		responseMap.put("approvals", approvals);
	}

	/**
	 * Method used for removing approval.
	 * @param approval - approval to be revoked.
	 */
	protected void removeApproval(Approval approval) {
		approvalStore.revokeApprovals(Arrays.asList(approval));
		tokenStore.findTokensByClientIdAndUserName(approval.getClientId(), approval.getUserId())
				.forEach(tokenStore::removeAccessToken);
	}
}
