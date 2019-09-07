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

/**
 * Model representing account activation token. It is stored in DB when user signs up to the page.
 * @author Dariusz Kulig
 *
 */
@Entity
public class AccountActivationToken {

	/**
	 * id - token id.
	 */
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	/**
	 * token - generated random string value used to reset the password.
	 */
	@Column(name = "token", nullable = false)
	@NotNull(message = "token cannot be empty.")
	private String token;

	/**
	 * user - user which signed up to the page.
	 */
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

	/**
	 * Getter for id field.
	 * @return id of account activation token.
	 */
	public Long getId() {
		return id;
	}

	/**
	 * Setter for id.
	 * @param id - token id.
	 */
	public void setId(Long id) {
		this.id = id;
	}

	/**
	 * Getter for token string value.
	 * @return token string value.
	 */
	public String getToken() {
		return token;
	}

	/**
	 * Setter for token field.
	 * @param token - token string value.
	 */
	public void setToken(String token) {
		this.token = token;
	}

	/**
	 * Getter for user.
	 * @return user entity.
	 */
	public AppUser getUser() {
		return user;
	}

	/**
	 * Setter for user.
	 * @param user - user signing up to the page.
	 */
	public void setUser(AppUser user) {
		this.user = user;
	}
}