package com.emles.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.validation.constraints.NotNull;

@Entity
public class AccountActivationToken {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(name = "token", nullable = false)
	@NotNull(message = "token cannot be empty.")
	private String token;

	@OneToOne(targetEntity = AppUser.class, fetch = FetchType.EAGER)
	@JoinColumn(nullable = false, name = "user_id")
	@NotNull(message = "user_id cannot be empty.")
	private AppUser user;

	public AccountActivationToken() {
	}

	public AccountActivationToken(String token, AppUser user) {
		this.token = token;
		this.user = user;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public AppUser getUser() {
		return user;
	}

	public void setUser(AppUser user) {
		this.user = user;
	}
}