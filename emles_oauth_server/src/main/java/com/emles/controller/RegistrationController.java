package com.emles.controller;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.emles.model.AppUser;
import com.emles.model.Passwords;
import com.emles.service.UserService;
import com.emles.utils.Utils;

@RestController
@RequestMapping("/user")
public class RegistrationController {

	@Autowired
	private UserService userService;

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
