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

	private static final String passwordRequirementsMsg = "It should contain at least one: digit, "
			+ "upper, lower case letter, special character and its length should be in range from 6 to 60 chars";

	public static final String invalidPasswordMsg = "Password is invalid. " + passwordRequirementsMsg;

	public static final String invalidPasswordConfirmationMsg = "Password confirmation is invalid. "
			+ passwordRequirementsMsg;

	public static final String passwordRegex = "(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{6,60}";

	public static final String passwordResetTokenCreatedMsg = "Check your email inbox for further instructions.";

	public static final String invalidEmailAddressMsg = "Invalid email address.";

	public static final String invalidPhoneNumberMsg = "Invalid phone number.";

	public static final String failedToChangeForgottenPassMsg = "Cannot reset your password. Try again later or reset password again.";

	public static final String passwordChangedSuccessMsg = "Your password has been changed.";

	public static final String passwordsNotEqualMsg = "Passwords are not equal.";

	public static final String oldPasswordInvalidMsg = "Old password is invalid. " + passwordRequirementsMsg;

	public static final String newPasswordInvalidMsg = "New password is invalid. " + passwordRequirementsMsg;

	public static final String newPasswordConfirmationInvalidMsg = "New password confirmation is invalid. "
			+ passwordRequirementsMsg;

	public static final String oldPasswordDoesNotMatch = "Old password does not match";

	public static final String updateUserDataSuccessMsg = "Your data has been updated.";

	public static final String emailExistsMsg = "Email already exists";

	public static final String phoneNumberExistsMsg = "Phone number already exists";

	public static final String userNameExistsMsg = "User name already exists";

	public static final String changedUserDataMsg = "User data has been changed";

	public static final String userDoesNotExistMsg = "User was not found";

	public static final String signUpSuccessMsg = "You have signed up successfully.";

	public static final String userCreatedSuccessMsg = "User has been created successfully.";

	public static final String invalidActivationTokenMsg = "Invalid activation token.";

	public static final String accountActivatedMsg = "Your account has been activated.";

	public static final String userNameRequirementMsg = "Username can contain only chars like numbers, underscores and letters."
			+ "Its length must be between 4 and 50 characters";

	public static final String userNameRegex = "^[A-Za-z0-9_]{4,50}$";

	public static final String phoneNumberRegex = "^(\\d{3}\\-?){2}\\d{3}$";

	public static final String accountRemovedMsg = "Account has been removed.";

	public static final String userEnabledMsg = "User has been enabled.";

	public static final String userDisabledMsg = "User has been disabled.";

	public static final String approvalRevokedMsg = "Approval has been revoked.";

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

	public static void removeTokens(OAuth2AccessToken accessToken, TokenStore tokenStore) {
		OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
		if (refreshToken != null) {
			tokenStore.removeRefreshToken(refreshToken);
		}
		tokenStore.removeAccessToken(accessToken);
	}
}
