package com.emles.controller;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.emles.model.AppUser;
import com.emles.model.Passwords;
import com.emles.model.UserData;
import com.emles.model.UserPasswords;
import com.emles.model.projection.UserSimplified;
import com.emles.utils.Utils;

@RestController
@RequestMapping("/user")
public class UsersController extends UserControllerBase {

	@PreAuthorize("hasAnyAuthority('ROLE_OAUTH_ADMIN', 'ROLE_PRODUCT_ADMIN', 'ROLE_USER')")
	@RequestMapping(value = "/revoke_my_approval", method = RequestMethod.POST)
	public ResponseEntity<?> revokeMyApproval(@RequestBody Approval approval) {
		String userId = SecurityContextHolder.getContext().getAuthentication().getName();
		if (approval.getUserId().equals(userId)) {
			Map<String, Object> responseMap = new HashMap<>();
			removeApproval(approval);
			responseMap.put("msg", Utils.approvalRevokedMsg);
			return ResponseEntity.ok().body(responseMap);
		}
		return ResponseEntity.badRequest().build();
	}

	@PreAuthorize("hasAnyAuthority('ROLE_OAUTH_ADMIN', 'ROLE_PRODUCT_ADMIN', 'ROLE_USER')")
	@RequestMapping(value = "/my_approvals", method = RequestMethod.GET)
	public ResponseEntity<?> myApprovals() {
		AppUser user = userService.findByName(SecurityContextHolder.getContext().getAuthentication().getName());
		Map<String, Object> responseMap = new HashMap<>();
		fetchApprovalList(responseMap, user);
		return ResponseEntity.ok().body(responseMap);
	}

	@PreAuthorize("hasAnyAuthority('ROLE_OAUTH_ADMIN', 'ROLE_PRODUCT_ADMIN', 'ROLE_USER')")
	@RequestMapping(value = "/my_account/delete", method = RequestMethod.DELETE)
	public ResponseEntity<?> deleteAccount() {
		AppUser user = userService.findByName(SecurityContextHolder.getContext().getAuthentication().getName());
		signOutUserRemotely(user);
		Map<String, Object> responseMap = new HashMap<>();
		responseMap.put("msg", Utils.accountRemovedMsg);
		userService.deleteUser(user.getId());
		return ResponseEntity.ok().body(responseMap);
	}

	@PreAuthorize("hasAnyAuthority('ROLE_OAUTH_ADMIN', 'ROLE_PRODUCT_ADMIN', 'ROLE_USER')")
	@RequestMapping(value = "/my_account", method = RequestMethod.GET)
	public ResponseEntity<?> showMyAccount() {
		UserSimplified user = userService
				.findSimplifiedByName(SecurityContextHolder.getContext().getAuthentication().getName());
		return ResponseEntity.ok().body(user);
	}

	@RequestMapping(value = "/validate_user_account", method = RequestMethod.POST)
	public ResponseEntity<?> validateUser(@RequestParam("id") long id, @RequestParam("token") String token) {
		Map<String, Object> responseMap = new HashMap<>();
		boolean result = userService.validateAccountActivationToken(id, token);

		if (!result) {
			responseMap.put("error", Utils.invalidActivationTokenMsg);
			return ResponseEntity.unprocessableEntity().body(responseMap);
		}
		responseMap.put("msg", Utils.accountActivatedMsg);
		return ResponseEntity.ok().body(responseMap);
	}

	@PreAuthorize("hasAnyAuthority('ROLE_OAUTH_ADMIN', 'ROLE_PRODUCT_ADMIN', 'ROLE_USER')")
	@RequestMapping(value = "/update_account", method = RequestMethod.PUT)
	public ResponseEntity<?> updateAccountData(@Valid @RequestBody UserData userData, Errors errors) {
		AppUser user = userService.findByName(SecurityContextHolder.getContext().getAuthentication().getName());
		return changeUserData(userData, errors, user);
	}

	@PreAuthorize("hasAnyAuthority('ROLE_OAUTH_ADMIN', 'ROLE_PRODUCT_ADMIN', 'ROLE_USER')")
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

		userService.updateUserPassword(user, passwords.getNewPassword());
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

	@RequestMapping(value = "/sign_up", method = RequestMethod.POST)
	public ResponseEntity<?> signUp(HttpServletRequest request, @Valid @RequestBody AppUser user, Errors errors) {
		return signUpNewUser(user, errors, false);
	}
}
