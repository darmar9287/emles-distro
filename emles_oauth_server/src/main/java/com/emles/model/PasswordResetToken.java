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

@Entity
public class PasswordResetToken {
  
    public PasswordResetToken(String token, AppUser user) {
    	this.token = token;
    	this.user = user;
    	this.expiryDate = Date.from(Instant.now().plus(Duration.ofDays(1)));
	}

	private static final int EXPIRATION = 60 * 24;
  
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
  
    @Column(name="token")
    @NotNull(message = "token cannot be empty.")
    private String token;
  
    @OneToOne(targetEntity = AppUser.class, fetch = FetchType.EAGER)
    @JoinColumn(nullable = false, name = "user_id")
    @NotNull(message = "user_id cannot be empty.")
    private AppUser user;
  
    @Column(name="expiry_date")
    @NotNull(message = "expiry_date cannot be empty.")
    private Date expiryDate;

    public PasswordResetToken() {}
    
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

	public Date getExpiryDate() {
		return expiryDate;
	}

	public void setExpiryDate(Date expiryDate) {
		this.expiryDate = expiryDate;
	}

	public static int getExpiration() {
		return EXPIRATION;
	}
}