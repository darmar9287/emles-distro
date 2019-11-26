package com.emles.utils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.validation.Errors;

/**
 * Utils class contains helper methods used in other packages/classes.
 * @author Dariusz Kulig
 *
 */
public final class Utils {

	private static final String passwordRequirementsMsg = "It should contain at least one: digit, "
			+ "upper, lower case letter, special character and its length should be in range from 6 to 60 chars";
	
	public static final String invalidPasswordMsg = "Password is invalid. " + passwordRequirementsMsg;
	
	public static final String invalidPasswordConfirmationMsg = "Password confirmation is invalid. " + passwordRequirementsMsg;
	
	public static final String passwordRegex = "(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{6,60}";
	
	public static final String productNameRegex = "^([\\w\\d\\S\\.\\/\\(\\)\\*]+[\\w\\s\\d\\.\\/\\(\\)\\*]*){3,255}\\S$";
	
	public static final String passwordResetTokenCreatedMsg = "Check your email inbox for further instructions.";
	
	public static final String invalidEmailAddressMsg = "Invalid email address.";
	
	public static final String failedToChangeForgottenPassMsg = "Cannot reset your password. Try again later or reset password again.";
	
	public static final String passwordChangedSuccessMsg = "Your password has been changed.";

	public static final String passwordsNotEqualMsg = "Passwords are not equal.";

	public static final String oldPasswordInvalidMsg = "Old password is invalid. " + passwordRequirementsMsg;

	public static final String newPasswordInvalidMsg = "New password is invalid. " + passwordRequirementsMsg;

	public static final String newPasswordConfirmationInvalidMsg = "New password confirmation is invalid. " + passwordRequirementsMsg;

	public static final String oldPasswordDoesNotMatch = "Old password does not match";
	
	public static final String updateUserDataSuccessMsg = "Your data has been updated.";
	
	public static final String emailExistsMsg = "Email already exists";
	
	public static final String phoneNumberExistsMsg = "Phone number already exists";
	
	public static final String userNameExistsMsg = "User name already exists";

	public static final String invalidProductQuantityMsg = "Product quantity cannot be less than zero";
	
	public static final String invalidProductNameMsg = "Product name is invalid";
	
	public static final String phoneNumberRegex = "^(\\d{3}\\-?){2}\\d{3}$";
	
	public static final String invalidPhoneNumberMsg = "Invalid phone number.";

	public static final String customerNameRegex = "^[A-Za-z]{2,100}\\s?[A-Za-z\\-]{0,100}$";

	public static final String invalidCustomerNameRegex = "Customer name is invalid.";
	
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
    
    public static List<Map<String, String>> extractErrorMessagesFromField(Errors errors) {
    	return errors.getFieldErrors().stream().map(error -> {
			Map<String, String> errorMap = new HashMap<>();
			errorMap.put(error.getField(), error.getDefaultMessage());
			return errorMap;
		}).collect(Collectors.toList());
    }
}
