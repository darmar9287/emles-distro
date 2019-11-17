package com.emles.model;

import javax.persistence.Column;
import javax.persistence.Embeddable;
import javax.persistence.Transient;
import javax.validation.constraints.Pattern;


import com.emles.utils.Utils;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonView;

/**
 * Sub-model representing passwords.
 * @author Dariusz Kulig
 *
 */
@Embeddable
public class Passwords {
	
	/**
	 * password - user password.
	 */
	@Pattern(regexp = Utils.passwordRegex, 
    		message = Utils.invalidPasswordMsg)
    @Column(name = "password")
	@JsonView(Views.Internal.class)
	@JsonIgnore
    private String password;
    
	/**
	 * passwordConfirmation - confirmation of user password.
	 * Not supposed to be stored in DB.
	 */
    @Pattern(regexp = Utils.passwordRegex, 
    message = Utils.invalidPasswordConfirmationMsg)
    @JsonProperty
    @Transient
    @JsonView(Views.Internal.class)
    @JsonIgnore
    private String passwordConfirmation;
    
    /**
	 * Getter for password.
	 * @return - password string value.
	 */
	public String getPassword() {
		return password;
	}

	/**
	 * Setter for password.
	 * @param password - password string value.
	 */
	public void setPassword(String password) {
		this.password = password;
	}

	/**
	 * Getter for passwordConfirmation.
	 * @return - passwordConfirmation string value.
	 */
	public String getPasswordConfirmation() {
		return passwordConfirmation;
	}

	/**
	 * Setter for newPasswordConfirmation.
	 * @param passwordConfirmation string value.
	 */
	public void setPasswordConfirmation(String passwordConfirmation) {
		this.passwordConfirmation = passwordConfirmation;
	}
}
