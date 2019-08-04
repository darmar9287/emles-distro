package com.emles.service;

import java.util.List;
import java.util.Optional;

import org.springframework.validation.Errors;

import com.emles.model.AppUser;
import com.emles.model.Passwords;
import com.emles.model.UserPasswords;

public interface UserService {

	Optional<AppUser> findById(long userId);

	AppUser findByName(String name);
	
	AppUser findByEmail(String email);

	boolean checkUsernameExists(String userName);

	void createPasswordResetTokenForUser(AppUser user, String token);

	void checkEqualityOfPasswords(AppUser user, List<String> errorMessages);

	void checkEqualityOfPasswords(String pass1, String pass2, List<String> errorMessages);

	String validatePasswordResetToken(long id, String token);

	void updateUserPasswordWithResetToken(AppUser user, Passwords passwords, String token);

	void checkOtherValidationErrors(Errors errors, List<String> errorMessages);

	void checkIfOldPasswordMatches(AppUser signedIn, String oldPassword, List<String> errorMessages);

	void updateUserPassword(AppUser signedIn, UserPasswords passwords);
}
