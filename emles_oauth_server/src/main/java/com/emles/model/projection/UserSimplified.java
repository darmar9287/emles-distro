package com.emles.model.projection;

import com.emles.model.UserData;

/**
 * Interface containing methods for retrieving non-sensitive data from AppUser model.
 * @author Dariusz Kulig
 */
public interface UserSimplified {

	/**
	 * Getter for user id field.
	 * @return user id.
	 */
	Long getId();

	/**
	 * Getter for username.
	 * @return user name string value.
	 */
	String getName();

	/**
	 * Getter for user data sub-model.
	 * @return user data instance object.
	 */
	UserData getUserData();
}
