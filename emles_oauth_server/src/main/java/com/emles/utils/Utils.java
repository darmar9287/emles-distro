package com.emles.utils;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Utils class contains helper methods used in other packages/classes.
 * @author Dariusz Kulig
 *
 */
public final class Utils {

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
