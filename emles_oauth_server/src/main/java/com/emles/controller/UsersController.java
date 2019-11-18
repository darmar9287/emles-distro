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

/**
 * Controller class containing endpoints for signed and not signed in users.
 * @author Dariusz Kulig
 *
 */
@RestController
@RequestMapping("/user")
public class UsersController extends UserControllerBase {

	/**
	 * Endpoint used for revoking approval for signed in user.
	 * @param approval - approval instance to be revoked.
	 * @return JSON object containing message about successful approval revocation. When approval data will be
	 * malformed, then 400 error will be sent.
	 */
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

	/**
	 * Endpoint where signed in user can view their approvals.
	 * @return JSON object containing list of approvals.
	 */
	@PreAuthorize("hasAnyAuthority('ROLE_OAUTH_ADMIN', 'ROLE_PRODUCT_ADMIN', 'ROLE_USER')")
	@RequestMapping(value = "/my_approvals", method = RequestMethod.GET)
	public ResponseEntity<?> myApprovals() {
		AppUser user = userService.findByName(SecurityContextHolder.getContext().getAuthentication().getName());
		Map<String, Object> responseMap = new HashMap<>();
		fetchApprovalList(responseMap, user);
		return ResponseEntity.ok().body(responseMap);
	}

	/**
	 * Endpoint where signed in user can delete his account. After this action user account will be removed and all
	 * tokens will be purged.
	 * @return JSON object containing message about successful account removal.
	 */
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

	/**
	 * Endpoint where signed in user can view his account data.
	 * @return JSON object conatining non-sensitive user data.
	 */
	@PreAuthorize("hasAnyAuthority('ROLE_OAUTH_ADMIN', 'ROLE_PRODUCT_ADMIN', 'ROLE_USER')")
	@RequestMapping(value = "/my_account", method = RequestMethod.GET)
	public ResponseEntity<?> showMyAccount() {
		UserSimplified user = userService
				.findSimplifiedByName(SecurityContextHolder.getContext().getAuthentication().getName());
		return ResponseEntity.ok().body(user);
	}

	/**
	 * Endpoint where user can activate his account with activation token.
	 * @param id - user id which used to activate account.
	 * @param token - token string value used to activate account.
	 * @return - JSON object containing error validation result when user id or token is invalid. When all data provided
	 * by user will be correct, then instead of error messages success message will be sent.
	 */
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

	/**
	 * Endpoint where signed in user can update his account.
	 * @param userData - new user data.
	 * @param errors - validation errors.
	 * @return JSON object containing validation errors or account update success message.
	 */
	@PreAuthorize("hasAnyAuthority('ROLE_OAUTH_ADMIN', 'ROLE_PRODUCT_ADMIN', 'ROLE_USER')")
	@RequestMapping(value = "/update_account", method = RequestMethod.PUT)
	public ResponseEntity<?> updateAccountData(@Valid @RequestBody UserData userData, Errors errors) {
		AppUser user = userService.findByName(SecurityContextHolder.getContext().getAuthentication().getName());
		return changeUserData(userData, errors, user);
	}

	/**
	 * Endpoint where signed in user can change his password. After successful password change, new access token will be
	 * generated.
	 * @param request - http servlet request with access token stored in headers.
	 * @param passwords - new user password.
	 * @param errors - validation errors.
	 * @return JSON object containing new access token and success message when all data will be correct. Otherwise
	 * validation error messages will be sent.
	 */
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

	/**
	 * Endpoint where all users can request for password reset token when they forget their password.
	 * @param email - email of user who's forgotten his password.
	 * @return JSON object containing error message when email address will be invalid. When all data will be correct,
	 * then successful message will be sent.
	 */
	@RequestMapping(value = "/forgot_password", method = RequestMethod.POST)
	public ResponseEntity<?> resetPassword(@RequestBody String email) {
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

	/**
	 * Endpoint where user sets new password after sending correct reset token.
	 * @param newPassword - new password to be set.
	 * @param errors - validation errors.
	 * @param id - user id who's requesting for a new password.
	 * @param token - account activation token.
	 * @return JSON object containing validation errors when token or user id or passwords will be invalid. If all data
	 * will be correct, then successful message will be returned.
	 */
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

	/**
	 * Endpoint where non signed in user can create new account.
	 * @param user - new user instance.
	 * @param errors - validation errors.
	 * @return JSON object containing validation errors or successful message when all data wil be correct.
	 */
	@RequestMapping(value = "/sign_up", method = RequestMethod.POST)
	public ResponseEntity<?> signUp(@Valid @RequestBody AppUser user, Errors errors) {
		return signUpNewUser(user, errors, false);
	}
}
