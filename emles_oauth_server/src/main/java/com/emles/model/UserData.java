package com.emles.model;

import javax.persistence.Column;
import javax.persistence.Embeddable;
import javax.validation.constraints.Email;
import javax.validation.constraints.Pattern;

import com.emles.utils.Utils;

/**
 * Sub-model representing unique user data.
 * @author Dariusz Kulig
 *
 */
@Embeddable
public class UserData {
	
	/**
	 * email - user email address.
	 */
	@Email(message = Utils.invalidEmailAddressMsg)
	@Column(name = "email", unique = true)
	private String email;

	/**
	 * phone - user phone number.
	 */
	@Pattern(regexp = Utils.phoneNumberRegex, message = Utils.invalidPhoneNumberMsg)
	@Column(name = "phone", unique = true)
	private String phone;
	
	/**
	 * Getter for email.
	 * @return - email string value.
	 */
	public String getEmail() {
		return email;
	}

	/**
	 * Setter for email.
	 * @param email string value.
	 */
	public void setEmail(String email) {
		this.email = email;
	}

	/**
	 * Getter for phone number.
	 * @return - phone string value.
	 */
	public String getPhone() {
		return phone;
	}

	/**
	 * Setter for phone.
	 * @param phone string value.
	 */
	public void setPhone(String phone) {
		this.phone = phone;
	}
}
