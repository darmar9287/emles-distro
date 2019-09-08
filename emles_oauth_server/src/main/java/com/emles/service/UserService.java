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

/**
 * Interface with business logic for AppUser model.
 * @author Dariusz Kulig
 *
 */
public interface UserService {

	/**
	 * Method used for retrieving user from DB by his id.
	 * @param userId - id of user to be found.
	 * @return optional value which should contain user for given id.
	 */
	Optional<AppUser> findById(long userId);

	/**
	 * Method used for retrieving user from DB by his name.
	 * @param name - name of user to be found.
	 * @return found user instance.
	 */
	AppUser findByName(String name);

	/**
	 * Method used for retrieving user from DB by his email.
	 * @param email - email of user to be found.
	 * @return found user instance.
	 */
	AppUser findByEmail(String email);

	/**
	 * Method used for checking if user name exists in DB.
	 * @param userName - user name to be check if it is stored in DB.
	 * @return true if user name was found.
	 */
	boolean checkUsernameExists(String userName);

	/**
	 * Method used for creating password reset token when user forgots his password.
	 * @param user - user who's requesting for reset token.
	 * @param token - random string value.
	 */
	void createPasswordResetTokenForUser(AppUser user, String token);

	/**
	 * Method used for checking if user passwords are equal.
	 * @param user - user who's creating/updating passwords.
	 * @param errorMessages - list containing validation errors when passwords will not be equal.
	 */
	void checkEqualityOfPasswords(AppUser user, List<String> errorMessages);

	/**
	 * Method used for checking if passwords are equal.
	 * @param pass1 - first password.
	 * @param pass2 - password confirmation.
	 * @param errorMessages - list containing validation errors when passwords will not be equal.
	 */
	void checkEqualityOfPasswords(String pass1, String pass2, List<String> errorMessages);

	/**
	 * Method used for validating password reset token.
	 * @param id - user id who's validating reset token.
	 * @param token - token sent by user.
	 * @return - string value which contains information when token is invalid.
	 */
	String validatePasswordResetToken(long id, String token);

	/**
	 * Method used for changing password with reset token.
	 * @param user - user instance who's password will be changed.
	 * @param passwords - new password with confirmation.
	 * @param token - token sent by user.
	 */
	void updateUserPasswordWithResetToken(AppUser user, Passwords passwords, String token);

	/**
	 * Method for merging Errors instance with errorMessages.
	 * @param errors - model validation errors.
	 * @param errorMessages - list containing other errors.
	 */
	void checkOtherValidationErrors(Errors errors, List<String> errorMessages);

	/**
	 * Method for checking if current password is correct with hash stored in DB.
	 * @param signedIn - user changing his password.
	 * @param oldPassword - current user password.
	 * @param errorMessages - validation errors list.
	 */
	void checkIfOldPasswordMatches(AppUser signedIn, String oldPassword, List<String> errorMessages);

	/**
	 * Method for updating user password.
	 * @param signedIn - user changing his password.
	 * @param newPassword - new password to be stored in DB.
	 */
	void updateUserPassword(AppUser signedIn, String newPassword);

	/**
	 * Method for validating unique values for user.
	 * @param user - user instance.
	 * @param errorMessages - validation errors list.
	 */
	void validateUniqueValuesForUser(AppUser user, List<String> errorMessages);

	/**
	 * Method for validating unique values for UserData model.
	 * @param userData - user data to be validated.
	 * @param errorMessages - validation errors list.
	 * @param signedIn - user instance who's data will be validated.
	 */
	void validateUniqueValuesForUserData(UserData userData, List<String> errorMessages, AppUser signedIn);

	/**
	 * Method for updating user data.
	 * @param user - user who's data will be updated.
	 * @param userData - user data to be applied.
	 */
	void updateUserData(AppUser user, UserData userData);

	/**
	 * Method for creating new user.
	 * @param user - user instance to be stored in DB.
	 * @param userRoles - Authorities which will be applied to the user.
	 * @return - instance of user saved in DB.
	 */
	AppUser createUser(AppUser user, Set<Authority> userRoles);

	/**
	 * Method for creating new user.
	 * @param user - user instance to be stored in DB.
	 */
	AppUser createUser(AppUser user);

	/**
	 * Method for creating activation token when user signs up to the page.
	 * @param user - user instance for which account token will be assigned.
	 * @param token - random string value.
	 */
	void createAccountActivationTokenForUser(AppUser user, String token);

	/**
	 * Method for validating account activation token.
	 * @param id - user id who's token will be checked.
	 * @param token - string value sent by user.
	 * @return true if account activation token is valid.
	 */
	boolean validateAccountActivationToken(long id, String token);

	/**
	 * Method for enabling/disabling user account.
	 * @param userId - user id who's account will be enabled/disabled.
	 * @return - true if user has been enabled.
	 */
	boolean toggleEnableUser(long userId);

	/**
	 * Method for saving user in DB with USER_ROLE.
	 * @param user - user instance to be stored in DB.
	 */
	void saveNewUserWithStandardRole(@Valid AppUser user);

	/**
	 * Method for listing limited amount of user instances.
	 * @param pageable - bounds used for retrieving users from DB.
	 * @return - Page instance containing list of users with pagination params.
	 */
	Page<UserSimplified> listUsers(Pageable pageable);

	/**
	 * Method for fetching user data without sensitive data.
	 * @param name - user name.
	 * @return UserSimplified instance containing non-sensitive data.
	 */
	UserSimplified findSimplifiedByName(String name);

	/**
	 * Method for changing user roles.
	 * @param appUser - user who's authorities will be changed.
	 * @param authorityIds - ids of authorities which will be applied to the user.
	 */
	void updateUserRoles(AppUser appUser, List<Long> authorityIds);

	/**
	 * Method for deleting user from DB.
	 * @param userId - id of user to be deleted.
	 */
	void deleteUser(Long userId);
}
