package com.emles.controller;

import java.util.ArrayList;
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
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.emles.model.AppUser;
import com.emles.model.Passwords;
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
    
    @Resource(name = "oauthServerTokenServices")
    private AuthorizationServerTokenServices tokenServices;
	
	@PreAuthorize("hasAnyAuthority('ROLE_OAUTH_ADMIN', 'ROLE_PRODUCT_ADMIN', 'ROLE_RESOURCE_ADMIN')")
	@RequestMapping(value="/change_password", method = RequestMethod.POST)
	public ResponseEntity<?> changePassword(HttpServletRequest request, @Valid @RequestBody UserPasswords passwords, Errors errors) {
		Map<String, Object> responseMap = new HashMap<>();
		List<String> errorMessages = new ArrayList<>();
		AppUser signedIn = userService.findByName(SecurityContextHolder.getContext()
                .getAuthentication().getName());
		
		userService.checkIfOldPasswordMatches(signedIn, passwords.getOldPassword(), errorMessages);
		userService.checkEqualityOfPasswords(passwords.getNewPassword(), passwords.getNewPasswordConfirmation(), errorMessages);
		userService.checkOtherValidationErrors(errors, errorMessages);
		
		if (errorMessages.size() > 0) {
			responseMap.put("validationErrors", errorMessages);
			return ResponseEntity.unprocessableEntity().body(responseMap);
		}
		
		userService.updateUserPassword(signedIn, passwords);
		OAuth2AccessToken accessToken = removeAccessTokens(request);

		accessToken = requestNewAccessToken(request, signedIn, accessToken);
		responseMap.put("msg", Utils.passwordChangedSuccessMsg);
		responseMap.put("token", accessToken);
		return ResponseEntity.ok().body(responseMap);
	}
	
	private OAuth2AccessToken requestNewAccessToken(HttpServletRequest request, AppUser signedIn, OAuth2AccessToken accessToken) {
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
		OAuth2Authentication authenticationRequest = new OAuth2Authentication(authRequest,
	            authenticationToken);
		authenticationRequest.setAuthenticated(true);
	    OAuth2AccessToken newToken = tokenServices.createAccessToken(authenticationRequest);
	    return newToken;
	}

	private OAuth2AccessToken removeAccessTokens(HttpServletRequest request) {
		String authorization = request.getHeader("Authorization");
		OAuth2AccessToken oauthAccessToken = null;
		if (authorization != null && authorization.contains("Bearer")) {
    		String tokenId = authorization.substring("Bearer".length() + 1);
    		oauthAccessToken = tokenStore.readAccessToken(tokenId);
    		if (oauthAccessToken != null) {
    			OAuth2RefreshToken refreshToken = oauthAccessToken.getRefreshToken();
    			if (refreshToken != null) {
    				tokenStore.removeRefreshToken(refreshToken);
    			}
    			tokenStore.removeAccessToken(oauthAccessToken);
    		}
    	}
		return oauthAccessToken;
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
	
	@RequestMapping(value="/change_forgotten_password", method = RequestMethod.POST)
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
	    userService.checkEqualityOfPasswords(newPassword.getPassword(), newPassword.getPasswordConfirmation(), errorMessages);
	    userService.checkOtherValidationErrors(errors, errorMessages);
	    if (errorMessages.size() > 0) {
			responseMap.put("validationErrors", errorMessages);
			return ResponseEntity.unprocessableEntity().body(responseMap);
		}
	    
		userService.updateUserPasswordWithResetToken(user, newPassword, token);
		responseMap.put("msg", Utils.passwordChangedSuccessMsg);
		return ResponseEntity.ok().body(responseMap);
	}
}
