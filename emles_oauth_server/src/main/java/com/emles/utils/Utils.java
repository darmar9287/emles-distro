package com.emles.utils;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

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
	
	public static final String passwordResetTokenCreatedMsg = "Check your email inbox for further instructions.";
	
	public static final String invalidEmailAddressMsg = "Invalid email address.";
	
	public static final String failedToChangeForgottenPassMsg = "Cannot reset your password. Try again later or reset password again.";
	
	public static final String passwordChangedSuccessMsg = "Your password has been changed.";
	
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
}
