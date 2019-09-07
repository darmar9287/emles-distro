package com.emles.model;

import javax.persistence.Column;
import javax.persistence.Embedded;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.Version;
import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;

import com.emles.utils.Utils;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

/**
 * AppUser model.
 * @author Dariusz Kulig
 *
 */
@Entity
@Table(name = "app_user")
public class AppUser implements Serializable {

	/**
	 * serialVersionUID - unique value needed for serialization.
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * id - credential id field in table.
	 */
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "user_id")
	private Long id;

	/**
	 * version - version of this object.
	 */
	@Version
	private Integer version;

	/**
	 * name - user login name.
	 */
	@NotEmpty
	@Pattern(regexp = Utils.userNameRegex, message = Utils.userNameRequirementMsg)
	@Column(name = "name", unique = true)
	private String name;

	/**
	 * passwords - password used to sign in/up.
	 */
	@Embedded
	@Valid
	@JsonView(Views.Internal.class)
	@JsonIgnore
	private Passwords passwords;

	/**
	 * lastPasswordResetDate - date of last password reset.
	 */
	@Column(name = "last_password_reset_date", nullable = false)
	@Temporal(TemporalType.TIMESTAMP)
	@JsonIgnore
	@JsonView(Views.Internal.class)
	private Date lastPasswordResetDate;

	/**
	 * userData - user unique data.
	 */
	@Embedded
	@Valid
	@JsonView(Views.Public.class)
	private UserData userData;

	/**
	 * authorities - list of granted authorities for a given user.
	 */
	@ManyToMany(fetch = FetchType.EAGER)
	private List<Authority> authorities;

	/**
	 * enabled - check if user can sign in.
	 */
	private boolean enabled;

	public AppUser() {
		this.passwords = new Passwords();
		this.userData = new UserData();
	}

	/**
	 * Getter for credential id.
	 * @return id of credential
	 */
	public Long getId() {
		return id;
	}

	/**
	 * Setter for credential id.
	 * @param credId - id of credential
	 */
	public void setId(Long credId) {
		this.id = credId;
	}

	/**
	 * Getter for version field.
	 * @return version field.
	 */
	public Integer getVersion() {
		return version;
	}

	/**
	 * Setter for version field.
	 * @param v - version of serialized object.
	 */
	public void setVersion(Integer v) {
		this.version = v;
	}

	/**
	 * Getter for name field.
	 * @return name of user who tries to log in.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Setter for name field.
	 * @param n - field name in credentials table.
	 */
	public void setName(String n) {
		this.name = n;
	}

	/**
	 * Getter for password field.
	 * @return password string value
	 */
	public String getPassword() {
		return this.passwords.getPassword();
	}

	/**
	 * Setter for password field.
	 * @param pass - password string value.
	 */
	public void setPassword(String pass) {
		this.passwords.setPassword(pass);
	}

	/**
	 * Getter for password confirmation field.
	 * @return password string value
	 */
	public String getPasswordConfirmation() {
		return this.passwords.getPasswordConfirmation();
	}

	/**
	 * Setter for password confirmation field.
	 * @param pass - password string value.
	 */
	public void setPasswordConfirmation(String pass) {
		this.passwords.setPasswordConfirmation(pass);
	}

	/**
	 * Getter for authorities.
	 * @return list of associated with this model authorities.
	 */
	public List<Authority> getAuthorities() {
		return authorities;
	}

	/**
	 * Setter for authorities.
	 * @param auths - authorities list
	 */
	public void setAuthorities(List<Authority> auths) {
		this.authorities = auths;
	}

	/**
	 * Getter for enabled field.
	 * @return enabled field.
	 */
	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * Setter for enabled field.
	 * @param en - boolean value for enabled user.
	 */
	public void setEnabled(boolean en) {
		this.enabled = en;
	}

	/**
	 * Getter for passwords field
	 * @return passwords field.
	 */
	public Passwords getPasswords() {
		return passwords;
	}

	/**
	 * Setter for passwords field.
	 * @param passwords - user passwords.
	 */
	public void setPasswords(Passwords passwords) {
		this.passwords = passwords;
	}

	/**
	 * Getter for lastPasswordResetDate field.
	 * @return lastPasswordResetDate field.
	 */
	public Date getLastPasswordResetDate() {
		return lastPasswordResetDate;
	}

	/**
	 * Setter for lastPasswordResetDate field.
	 * @param lastPasswordResetDate - last password reset date.
	 */
	public void setLastPasswordResetDate(Date lastPasswordResetDate) {
		this.lastPasswordResetDate = lastPasswordResetDate;
	}

	/**
	 * Getter for email address.
	 * @return email address string value.
	 */
	public String getEmail() {
		return userData.getEmail();
	}

	/**
	 * Setter for email address.
	 * @param email - email string value.
	 */
	public void setEmail(String email) {
		this.userData.setEmail(email);
	}

	/**
	 * Getter for phone number.
	 * @return phone number string value.
	 */
	public String getPhone() {
		return userData.getPhone();
	}

	/**
	 * Setter for phone number.
	 * @param phone - phone number string value.
	 */
	public void setPhone(String phone) {
		userData.setPhone(phone);
	}

	/**
	 * Getter for user data values.
	 * @return userData reference.
	 */
	public UserData getUserData() {
		return userData;
	}

	/**
	 * Setter for user data values.
	 * @param userData - new user data values.
	 */
	public void setUserData(UserData userData) {
		this.userData = userData;
	}
}
