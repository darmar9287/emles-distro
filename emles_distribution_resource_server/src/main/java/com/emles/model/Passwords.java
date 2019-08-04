package com.emles.model;

import javax.persistence.Column;
import javax.persistence.Embeddable;
import javax.persistence.Transient;
import javax.validation.constraints.Pattern;

import com.emles.utils.Utils;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonView;

@Embeddable
public class Passwords {
	@Pattern(regexp = Utils.passwordRegex, 
    		message = Utils.invalidPasswordMsg)
    @Column(name = "password")
	@JsonView(Views.Internal.class)
    private String password;
    
    @Pattern(regexp = Utils.passwordRegex, 
    message = Utils.invalidPasswordConfirmationMsg)
    @JsonProperty
    @Transient
    @JsonView(Views.Internal.class)
    private String passwordConfirmation;

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getPasswordConfirmation() {
		return passwordConfirmation;
	}

	public void setPasswordConfirmation(String passwordConfirmation) {
		this.passwordConfirmation = passwordConfirmation;
	}
}