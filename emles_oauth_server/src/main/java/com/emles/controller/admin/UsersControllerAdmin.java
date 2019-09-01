package com.emles.controller.admin;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.emles.controller.UserControllerBase;
import com.emles.model.AppUser;
import com.emles.model.Authority;
import com.emles.model.UserData;
import com.emles.model.UserPasswords;
import com.emles.model.projection.UserSimplified;
import com.emles.utils.Utils;

@RestController
@RequestMapping("/admin/user")
public class UsersControllerAdmin extends UserControllerBase {

	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	@RequestMapping(value = "/sign_user_out/{userId}", method = RequestMethod.POST)
	public ResponseEntity<?> signUserOut(@PathVariable("userId") Long userId) {
		Optional<AppUser> userOpt = userService.findById(userId);
		if (userOpt.isPresent()) {
			Map<String, Object> responseMap = new HashMap<>();
			signOutUserRemotely(userOpt.get());
			responseMap.put("msg", Utils.userSignedOutMsg);
			return ResponseEntity.ok().body(responseMap);
		}
		return ResponseEntity.notFound().build();
	}

	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	@RequestMapping(value = "/revoke_approval", method = RequestMethod.POST)
	public ResponseEntity<?> revokeApproval(@RequestBody Approval approval) {
		Map<String, Object> responseMap = new HashMap<>();
		removeApproval(approval);
		responseMap.put("msg", Utils.approvalRevokedMsg);
		return ResponseEntity.ok().body(responseMap);
	}

	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	@RequestMapping(value = "/user_approvals/{userId}", method = RequestMethod.GET)
	public ResponseEntity<?> showUserApprovals(@PathVariable("userId") Long userId) {
		Optional<AppUser> userOpt = userService.findById(userId);
		Map<String, Object> responseMap = new HashMap<>();
		if (userOpt.isPresent()) {
			AppUser user = userOpt.get();
			fetchApprovalList(responseMap, user);
			return ResponseEntity.ok().body(responseMap);
		}

		return ResponseEntity.notFound().build();
	}

	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	@RequestMapping(value = "/toggle_enable_user/{userId}", method = RequestMethod.PUT)
	public ResponseEntity<?> toggleEnableUser(@PathVariable("userId") Long userId) {
		Optional<AppUser> userOpt = userService.findById(userId);
		if (userOpt.isPresent()) {
			Map<String, Object> responseMap = new HashMap<>();
			signOutUserRemotely(userOpt.get());

			boolean userEnabled = userService.toggleEnableUser(userId);
			responseMap.put("msg", userEnabled ? Utils.userEnabledMsg : Utils.userDisabledMsg);
			return ResponseEntity.ok().body(responseMap);
		}

		return ResponseEntity.notFound().build();
	}

	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	@RequestMapping(value = "/delete_account/{userId}", method = RequestMethod.DELETE)
	public ResponseEntity<?> deleteAccountByAdmin(@PathVariable("userId") Long userId) {
		Optional<AppUser> userOpt = userService.findById(userId);
		if (userOpt.isPresent()) {
			Map<String, Object> responseMap = new HashMap<>();
			signOutUserRemotely(userOpt.get());
			responseMap.put("msg", Utils.accountRemovedMsg);
			userService.deleteUser(userId);
			return ResponseEntity.ok().body(responseMap);
		}

		return ResponseEntity.notFound().build();
	}

	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	@RequestMapping(value = "/{userId}/update_roles", method = RequestMethod.PUT)
	public ResponseEntity<?> updateUserRoles(@PathVariable(name = "userId", required = true) long userId,
			@RequestBody List<Long> authorityIds) {
		Optional<AppUser> userOpt = userService.findById(userId);
		if (userOpt.isPresent()) {
			Map<String, Object> responseMap = new HashMap<>();
			responseMap.put("msg", Utils.updateUserDataSuccessMsg);
			userService.updateUserRoles(userOpt.get(), authorityIds);
			return ResponseEntity.ok().body(responseMap);
		}
		return ResponseEntity.notFound().build();
	}

	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	@RequestMapping(value = "/show/{userId}", method = RequestMethod.GET)
	public ResponseEntity<?> showUserForAdmin(@PathVariable(name = "userId", required = true) long userId) {
		Optional<AppUser> userOpt = userService.findById(userId);
		if (userOpt.isPresent()) {
			Map<String, Object> responseMap = new HashMap<>();
			AppUser user = userOpt.get();
			responseMap.put("name", user.getName());
			responseMap.put("authorities", user.getAuthorities().stream().map(Authority::getAuthority).toArray());
			responseMap.put("email", user.getEmail());
			responseMap.put("phone", user.getPhone());
			responseMap.put("id", user.getId());
			responseMap.put("enabled", user.isEnabled());
			return ResponseEntity.ok().body(responseMap);
		}
		return ResponseEntity.notFound().build();
	}

	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	@RequestMapping(value = { "/users/{page}", "/users" }, method = RequestMethod.GET)
	public Page<UserSimplified> showUsers(@PathVariable(name = "page", required = false) Integer page) {
		if (page == null) {
			page = 0;
		}
		Pageable pageable = PageRequest.of(page, PER_PAGE);
		return userService.listUsers(pageable);
	}

	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	@RequestMapping(value = "/create_user", method = RequestMethod.POST)
	public ResponseEntity<?> createUser(HttpServletRequest request, @Valid @RequestBody AppUser user, Errors errors) {
		return signUpNewUser(user, errors, true);
	}

	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	@RequestMapping(value = "/update_account/{userId}", method = RequestMethod.PUT)
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

	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	@RequestMapping(value = "/change_password/{userId}", method = RequestMethod.POST)
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
}
