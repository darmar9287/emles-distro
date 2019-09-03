package com.emles.service;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import javax.validation.Valid;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.validation.Errors;

import com.emles.model.AppUser;
import com.emles.model.Authority;
import com.emles.model.Passwords;
import com.emles.model.UserData;
import com.emles.model.projection.UserSimplified;

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

	void updateUserPassword(AppUser signedIn, String newPassword);

	void validateUniqueValuesForUser(AppUser user, List<String> errorMessages);

	void validateUniqueValuesForUserData(UserData userData, List<String> errorMessages, AppUser signedIn);

	void updateUserData(AppUser user, UserData userData);

	AppUser createUser(AppUser user, Set<Authority> userRoles);

	AppUser createUser(AppUser user);

	void createAccountActivationTokenForUser(AppUser user, String token);

	boolean validateAccountActivationToken(long id, String token);

	boolean toggleEnableUser(long userId);

	void saveNewUserWithStandardRole(@Valid AppUser user);

	Page<UserSimplified> listUsers(Pageable pageable);

	UserSimplified findSimplifiedByName(String name);

	void updateUserRoles(AppUser appUser, List<Long> authorityIds);

	void deleteUser(Long userId);
}
