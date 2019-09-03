package com.emles.model;

import javax.validation.constraints.Pattern;

import com.emles.utils.Utils;

/**
 * Class used in changing
 * password when user is signed in.
 * @author Dariusz Kulig
 *
 */
public class UserPasswords {

	/**
	 * oldPassword - password which will be changed.
	 */
	@Pattern(regexp = Utils.passwordRegex, 
		    message = Utils.oldPasswordInvalidMsg)
	private String oldPassword;
	
	/**
	 * newPassword - new credentials.
	 */
	@Pattern(regexp = Utils.passwordRegex, 
		    message = Utils.newPasswordInvalidMsg)
	private String newPassword;
	
	/**
	 * newPasswordConfirmation - confirmation of new credentials.
	 */
	@Pattern(regexp = Utils.passwordRegex, 
		    message = Utils.newPasswordConfirmationInvalidMsg)
	private String newPasswordConfirmation;
	
	/**
	 * Getter for oldPassword.
	 * @return - oldPassword string value.
	 */
	public String getOldPassword() {
		return oldPassword;
	}
	
	/**
	 * Setter for oldPassword.
	 * @param oldPassword string value.
	 */
	public void setOldPassword(String oldPassword) {
		this.oldPassword = oldPassword;
	}
	
	/**
	 * Getter for newPassword.
	 * @return - newPassword string value.
	 */
	public String getNewPassword() {
		return newPassword;
	}
	
	/**
	 * Setter for newPassword.
	 * @param newPassword string value.
	 */
	public void setNewPassword(String newPassword) {
		this.newPassword = newPassword;
	}
	
	/**
	 * Getter for newPasswordConfirmation.
	 * @return - newPasswordConfirmation string value.
	 */
	public String getNewPasswordConfirmation() {
		return newPasswordConfirmation;
	}
	
	/**
	 * Setter for newPasswordConfirmation.
	 * @param newPasswordConfirmation string value.
	 */
	public void setNewPasswordConfirmation(String newPasswordConfirmation) {
		this.newPasswordConfirmation = newPasswordConfirmation;
	}
}
