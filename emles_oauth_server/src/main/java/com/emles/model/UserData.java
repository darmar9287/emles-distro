package com.emles.model;

import javax.persistence.Column;
import javax.persistence.Embeddable;
import javax.validation.constraints.Email;
import javax.validation.constraints.Pattern;

import com.emles.utils.Utils;

@Embeddable
public class UserData {
	
	@Email(message = Utils.invalidEmailAddressMsg)
	@Column(name = "email", unique = true)
	private String email;

	@Pattern(regexp = Utils.phoneNumberRegex, message = Utils.invalidPhoneNumberMsg)
	@Column(name = "phone", unique = true)
	private String phone;
	
	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPhone() {
		return phone;
	}

	public void setPhone(String phone) {
		this.phone = phone;
	}
}