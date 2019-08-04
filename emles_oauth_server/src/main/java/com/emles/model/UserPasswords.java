package com.emles.model;

import javax.validation.constraints.Pattern;

import com.emles.utils.Utils;

public class UserPasswords {

	@Pattern(regexp = Utils.passwordRegex, 
		    message = Utils.oldPasswordInvalidMsg)
	private String oldPassword;
	
	@Pattern(regexp = Utils.passwordRegex, 
		    message = Utils.newPasswordInvalidMsg)
	private String newPassword;
	
	@Pattern(regexp = Utils.passwordRegex, 
		    message = Utils.newPasswordConfirmationInvalidMsg)
	private String newPasswordConfirmation;
	
	public String getOldPassword() {
		return oldPassword;
	}
	public void setOldPassword(String oldPassword) {
		this.oldPassword = oldPassword;
	}
	public String getNewPassword() {
		return newPassword;
	}
	public void setNewPassword(String newPassword) {
		this.newPassword = newPassword;
	}
	public String getNewPasswordConfirmation() {
		return newPasswordConfirmation;
	}
	public void setNewPasswordConfirmation(String newPasswordConfirmation) {
		this.newPasswordConfirmation = newPasswordConfirmation;
	}
}