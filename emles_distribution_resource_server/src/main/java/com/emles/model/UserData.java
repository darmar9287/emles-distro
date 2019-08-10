package com.emles.model;

import javax.persistence.Embeddable;
import javax.validation.constraints.Email;
import javax.validation.constraints.Pattern;

import com.emles.utils.Utils;

@Embeddable
public class UserData {
	
	@Email(message = Utils.emailExistsMsg)
	private String email;

	@Pattern(regexp = "^(\\d{3}\\-?){2}\\d{3}$", message = Utils.phoneNumberExistsMsg)
	private String phoneNumber;
	
	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPhoneNumber() {
		return phoneNumber;
	}

	public void setPhoneNumber(String phoneNumber) {
		this.phoneNumber = phoneNumber;
	}
}