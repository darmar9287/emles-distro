package com.emles.utils;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * Utils class contains helper methods used in other packages/classes.
 * @author Dariusz Kulig
 *
 */
public final class Utils {

	/**
	 * passwordRequirementMsg - string message which will be returned when passwords will be invalid.
	 */
	private static final String passwordRequirementsMsg = "It should contain at least one: digit, "
			+ "upper, lower case letter, special character and its length should be in range from 6 to 60 chars";

	/**
	 * invalidPasswordMsg - message returned when user password will be invalid.
	 */
	public static final String invalidPasswordMsg = "Password is invalid. " + passwordRequirementsMsg;

	/**
	 * invalidPasswordConfirmationMsg - message returned when password confirmation will be invalid.
	 */
	public static final String invalidPasswordConfirmationMsg = "Password confirmation is invalid. "
			+ passwordRequirementsMsg;

	/**
	 * passwordRegex - regular expression for password.
	 */
	public static final String passwordRegex = "(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{6,60}";

	/**
	 * passwordResetTokenCreatedMsg - message returned to the client when user requests forgot_password endpoint.
	 */
	public static final String passwordResetTokenCreatedMsg = "Check your email inbox for further instructions.";

	/**
	 * invalidEmailAddressMsg - message returned to the client when she enters invalid email address.
	 */
	public static final String invalidEmailAddressMsg = "Invalid email address.";

	/**
	 * invalidPhoneNumberMsg - message returned to the client when she enters invalid phone number.
	 */
	public static final String invalidPhoneNumberMsg = "Invalid phone number.";

	/**
	 * failedToChangeForgottenPassMsg - message returned to the client when script fails to update password eg. invalid
	 * reset token or user id.
	 */
	public static final String failedToChangeForgottenPassMsg = "Cannot reset your password. Try again later or reset password again.";

	/**
	 * passwordChangedSuccessMsg - message returned to the client when her password will be changed.
	 */
	public static final String passwordChangedSuccessMsg = "Your password has been changed.";

	/**
	 * passwordsNotEqualMsg - message returned to the client when password and password confirmation will not be equal.
	 */
	public static final String passwordsNotEqualMsg = "Passwords are not equal.";

	/**
	 * oldPasswordInvalidMsg - message returned to the client when current password will be invalid.
	 */
	public static final String oldPasswordInvalidMsg = "Old password is invalid. " + passwordRequirementsMsg;

	/**
	 * newPasswordInvalidMsg - message returned to the client when new password will be invalid.
	 */
	public static final String newPasswordInvalidMsg = "New password is invalid. " + passwordRequirementsMsg;

	/**
	 * newPasswordConfirmationInvalidMsg - message returned to the client when new password and its confirmation will
	 * not be equal.
	 */
	public static final String newPasswordConfirmationInvalidMsg = "New password confirmation is invalid. "
			+ passwordRequirementsMsg;

	/**
	 * oldPasswordDoesNotMatch - message returned to the client when current password hash will be invalid with hash
	 * stored in db.
	 */
	public static final String oldPasswordDoesNotMatch = "Old password does not match";

	/**
	 * updateUserDataSuccessMsg - message returned to the client when user data will be changed successfully.
	 */
	public static final String updateUserDataSuccessMsg = "Your data has been updated.";

	/**
	 * emailExistsMsg - message returned to the client when email exists in db.
	 */
	public static final String emailExistsMsg = "Email already exists";

	/**
	 * phoneNumberExistsMsg - message returned to the client when phone number exists in db.
	 */
	public static final String phoneNumberExistsMsg = "Phone number already exists";

	/**
	 * userNameExistsMsg - message returned to the client when username exists in db.
	 */
	public static final String userNameExistsMsg = "User name already exists";

	/**
	 * changedUserDataMsg - message returned to the client when her data will be changed successfully.
	 */
	public static final String changedUserDataMsg = "User data has been changed";

	/**
	 * userDoesNotExistMsg - message returned to the client when user will not be found in db.
	 */
	public static final String userDoesNotExistMsg = "User was not found";

	/**
	 * signUpSuccessMsg - message returned to the client when user signs up successfully.
	 */
	public static final String signUpSuccessMsg = "You have signed up successfully.";

	/**
	 * userCreatedSuccessMsg - message returned to the client when user will be created successfully.
	 */
	public static final String userCreatedSuccessMsg = "User has been created successfully.";

	/**
	 * invalidActivationTokenMsg - message returned to the client when account activation token will be invalid.
	 */
	public static final String invalidActivationTokenMsg = "Invalid activation token.";

	/**
	 * accountActivatedMsg - message returned to the client when account will be activated.
	 */
	public static final String accountActivatedMsg = "Your account has been activated.";

	/**
	 * userNameRequirementMsg - message returned to the client when username will be invalid.
	 */
	public static final String userNameRequirementMsg = "Username can contain only chars like numbers, underscores and letters."
			+ "Its length must be between 4 and 50 characters";

	/**
	 * userNameRegex - regex for username.
	 */
	public static final String userNameRegex = "^[A-Za-z0-9_]{4,50}$";

	/**
	 * phoneNumberRegex - regex for phone number.
	 */
	public static final String phoneNumberRegex = "^(\\d{3}\\-?){2}\\d{3}$";

	/**
	 * accountRemovedMsg - message returned to the client when account will be deleted.
	 */
	public static final String accountRemovedMsg = "Account has been removed.";

	/**
	 * userEnabledMsg - message returned to the client when her account will be enabled.
	 */
	public static final String userEnabledMsg = "User has been enabled.";

	/**
	 * userDisabledMsg - message returned to the client when her account will be disabled.
	 */
	public static final String userDisabledMsg = "User has been disabled.";

	/**
	 * approvalRevokedMsg - message returned to the client when given approval will be revoked.
	 */
	public static final String approvalRevokedMsg = "Approval has been revoked.";

	/**
	 * userSignedOutMsg - message returned to the client when she signs out.
	 */
	public static final String userSignedOutMsg = "User has been signed out.";

	/**
	 * Method used to encode user password.
	 * @param password - password to be encoded.
	 * @return encoded password hash.
	 */
	public static String passwordEncoder(String password) {

		PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		String encodedPassword = passwordEncoder.encode(password);

		return encodedPassword;
	}

	/**
	 * Method used to remove access and refresh tokens from token store.
	 * @param accessToken - access token to be removed.
	 * @param tokenStore - token store where access token is stored.
	 */
	public static void removeTokens(OAuth2AccessToken accessToken, TokenStore tokenStore) {
		OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
		if (refreshToken != null) {
			tokenStore.removeRefreshToken(refreshToken);
		}
		tokenStore.removeAccessToken(accessToken);
	}
}
