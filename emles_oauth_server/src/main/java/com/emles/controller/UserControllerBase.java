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
import com.emles.model.UserData;
import com.emles.model.UserPasswords;
import com.emles.service.UserService;
import com.emles.utils.Utils;

public abstract class UserControllerBase {

	protected int PER_PAGE;

	protected UserService userService;

	/**
	 * tokenStore - used for caching access tokens.
	 */
	protected TokenStore tokenStore;

	protected JdbcClientDetailsService clientDetailsService;

	protected ApprovalStore approvalStore;

	protected AuthorizationServerTokenServices tokenServices;

	@Autowired
	public final void setUserService(UserService userService) {
		this.userService = userService;
	}

	@Autowired
	public final void setTokenStore(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
	}

	@Autowired
	public final void setClientDetailsService(JdbcClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	@Autowired
	public final void setApprovalStore(ApprovalStore approvalStore) {
		this.approvalStore = approvalStore;
	}

	@Resource(name = "oauthServerTokenServices")
	public final void setTokenServices(AuthorizationServerTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}

	@Value("${config.pagination.per_page}")
	public final void setPerPage(int perPage) {
		this.PER_PAGE = perPage;
	}

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

	protected void validateUserPasswords(UserPasswords passwords, Errors errors, List<String> errorMessages,
			AppUser user) {
		userService.checkIfOldPasswordMatches(user, passwords.getOldPassword(), errorMessages);
		userService.checkEqualityOfPasswords(passwords.getNewPassword(), passwords.getNewPasswordConfirmation(),
				errorMessages);
		userService.checkOtherValidationErrors(errors, errorMessages);
	}

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

	protected void fetchApprovalList(Map<String, Object> responseMap, AppUser user) {
		List<Approval> approvals = clientDetailsService.listClientDetails().stream()
				.map(clientDetails -> approvalStore.getApprovals(user.getName(), clientDetails.getClientId()))
				.flatMap(Collection::stream).collect(Collectors.toList());
		responseMap.put("approvals", approvals);
	}

	protected void removeApproval(Approval approval) {
		approvalStore.revokeApprovals(Arrays.asList(approval));
		tokenStore.findTokensByClientIdAndUserName(approval.getClientId(), approval.getUserId())
				.forEach(tokenStore::removeAccessToken);
	}
}
