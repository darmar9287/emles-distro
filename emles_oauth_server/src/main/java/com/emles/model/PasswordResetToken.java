package com.emles.model;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

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
 * Model representing password reset token. It is stored in DB when user sends forgot_password request to the endpoint.
 * @author Dariusz Kulig
 *
 */
@Entity
public class PasswordResetToken {

	/**
	 * EXPIRATION - token expiration in minutes.
	 */
	private static final int EXPIRATION = 60 * 24;

	/**
	 * id - token id.
	 */
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	/**
	 * token - generated random string value used to reset the password.
	 */
	@Column(name = "token")
	@NotNull(message = "token cannot be empty.")
	private String token;

	/**
	 * user - user which requested password reset token.
	 */
	@OneToOne(targetEntity = AppUser.class, fetch = FetchType.EAGER)
	@JoinColumn(nullable = false, name = "user_id")
	@NotNull(message = "user_id cannot be empty.")
	private AppUser user;

	/**
	 * expiryDate - date of reset token expiration.
	 */
	@Column(name = "expiry_date")
	@NotNull(message = "expiry_date cannot be empty.")
	private Date expiryDate;

	/**
	 * Arg constructor for PasswordResetToken class.
	 * @param token - generated random string value used to reset the password.
	 * @param user - user which requested password reset token.
	 */
	public PasswordResetToken(String token, AppUser user) {
		this.token = token;
		this.user = user;
		this.expiryDate = Date.from(Instant.now().plus(Duration.ofDays(1)));
	}

	/**
	 * No-arg constructor for PasswordResetToken class.
	 */
	public PasswordResetToken() {
	}

	/**
	 * Getter for id field.
	 * @return id of password reset token.
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
	 * @param user - user requesting password reset token.
	 */
	public void setUser(AppUser user) {
		this.user = user;
	}

	/**
	 * Getter for expiryDate.
	 * @return password reset token expiration date.
	 */
	public Date getExpiryDate() {
		return expiryDate;
	}

	/**
	 * Setter for expiryDate.
	 * @param expiryDate - date of token expiration.
	 */
	public void setExpiryDate(Date expiryDate) {
		this.expiryDate = expiryDate;
	}

	/**
	 * Getter for EXPIRATION constant.
	 * @return EXPIRATION value.
	 */
	public static int getExpiration() {
		return EXPIRATION;
	}
}