package com.emles.service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.Errors;
import com.emles.model.AccountActivationToken;
import com.emles.model.AppUser;
import com.emles.model.Authority;
import com.emles.model.PasswordResetToken;
import com.emles.model.Passwords;
import com.emles.model.UserData;
import com.emles.model.projection.UserSimplified;
import com.emles.repository.AccountActivationTokenRepository;
import com.emles.repository.AppUserRepository;
import com.emles.repository.AuthorityRepository;
import com.emles.repository.PasswordTokenRepository;
import com.emles.utils.Utils;

/**
 * Implementation of UserService interface.
 * @author Dariusz Kulig
 *
 */
@Service
public class UserServiceImpl implements UserService {

	/**
	 * userRepository - repository which manages AppUser instances in db.
	 */
	@Autowired
	private AppUserRepository userRepository;

	/**
	 * passwordEncoder - encoder for user password.
	 */
	@Autowired
	private PasswordEncoder passwordEncoder;

	/**
	 * passwordTokenRepository - repository which manages PasswordResetToken instances in db.
	 */
	@Autowired
	private PasswordTokenRepository passwordTokenRepository;

	/**
	 * authoritRepository - repository which manages Authority instances in db.
	 */
	@Autowired
	private AuthorityRepository authorityRepository;

	/**
	 * accountActivationTokenRepository - repository which manages AccountActivationToken instances in db.
	 */
	@Autowired
	private AccountActivationTokenRepository accountActivationTokenRepository;

	@Transactional
	public Optional<AppUser> findById(long userId) {
		return userRepository.findById(userId);
	}

	@Transactional
	public AppUser findByName(String name) {
		return userRepository.findByName(name);
	}

	@Transactional
	public AppUser findByEmail(String email) {
		return userRepository.findByUserDataEmail(email);
	}

	@Transactional
	public boolean checkUsernameExists(String userName) {
		return findByName(userName) != null;
	}

	@Transactional
	public void createPasswordResetTokenForUser(AppUser user, String token) {
		PasswordResetToken resetToken = passwordTokenRepository.findByUser(user);
		if (resetToken != null) {
			passwordTokenRepository.delete(resetToken);
		}

		resetToken = new PasswordResetToken(token, user);
		user.setLastPasswordResetDate(Date.from(Instant.now()));
		passwordTokenRepository.save(resetToken);
		userRepository.save(user);
	}

	@Transactional
	public void checkEqualityOfPasswords(AppUser user, List<String> errorMessages) {
		checkEqualityOfPasswords(user.getPassword(), user.getPasswordConfirmation(), errorMessages);
	}

	@Transactional
	public void checkEqualityOfPasswords(String pass1, String pass2, List<String> errorMessages) {
		if (!checkPasswordsAreEqual(pass1, pass2)) {
			errorMessages.add(Utils.passwordsNotEqualMsg);
		}
	}

	@Transactional
	public String validatePasswordResetToken(long id, String token) {
		PasswordResetToken passToken = passwordTokenRepository.findByToken(token);
		if ((passToken == null) || (passToken.getUser().getId() != id)) {
			return "invalidToken";
		}

		if (isTokenExpired(passToken)) {
			passwordTokenRepository.delete(passToken);
			return "expired";
		}

		return null;
	}

	@Transactional
	public void updateUserPasswordWithResetToken(AppUser user, Passwords passwords, String token) {
		user.setPasswords(passwords);
		String encryptedPassword = passwordEncoder.encode(user.getPassword());
		user.setPassword(encryptedPassword);
		user.setLastPasswordResetDate(Date.from(Instant.now()));
		userRepository.save(user);
		PasswordResetToken passToken = passwordTokenRepository.findByToken(token);
		passwordTokenRepository.delete(passToken);
	}

	@Transactional
	public void updateUserData(AppUser user, UserData userData) {
		user.setUserData(userData);
		userRepository.save(user);
	}

	@Transactional
	public void validateUniqueValuesForUser(AppUser user, List<String> errorMessages) {
		checkIfUserNameExistsInDb(user, errorMessages);
		checkIfEmailExistsInDb(user.getUserData().getEmail(), errorMessages);
		checkIfPhoneNumberExistsInDb(user.getUserData().getPhone(), errorMessages);
	}

	@Override
	public void checkOtherValidationErrors(Errors errors, List<String> errorMessages) {
		if (errors.hasErrors()) {
			errors.getAllErrors().forEach(error -> {
				errorMessages.add(error.getDefaultMessage());
			});
		}
	}

	@Override
	public void checkIfOldPasswordMatches(AppUser signedIn, String oldPassword, List<String> errorMessages) {
		if (!passwordEncoder.matches(oldPassword, signedIn.getPassword())) {
			errorMessages.add(Utils.oldPasswordDoesNotMatch);
		}
	}

	@Transactional
	public void updateUserPassword(AppUser signedIn, String newPassword) {
		String encryptedPassword = passwordEncoder.encode(newPassword);
		signedIn.setPassword(encryptedPassword);
		userRepository.save(signedIn);
	}

	@Transactional
	public void validateUniqueValuesForUserData(UserData userData, List<String> errorMessages, AppUser signedIn) {
		String userDataPhone = userData.getPhone().replaceAll("\\-", "");
		String signedInUserDataPhone = signedIn.getPhone().replaceAll("\\-", "");
		if (!userDataPhone.equals(signedInUserDataPhone)) {
			checkIfPhoneNumberExistsInDb(userDataPhone, errorMessages);
		}
		if (!userData.getEmail().equals(signedIn.getEmail())) {
			checkIfEmailExistsInDb(userData.getEmail(), errorMessages);
		}
	}

	@Transactional
	public AppUser createUser(AppUser user, Set<Authority> userRoles) {
		String encryptedPassword = passwordEncoder.encode(user.getPassword());
		user.setPassword(encryptedPassword);
		user.setAuthorities(new ArrayList<Authority>());
		user.setEnabled(false);
		user.setLastPasswordResetDate(Date.from(Instant.now()));

		for (Authority ur : userRoles) {
			authorityRepository.save(ur);
		}

		user.getAuthorities().addAll(userRoles);

		return userRepository.save(user);
	}

	@Transactional
	public AppUser createUser(AppUser user) {
		user.setEnabled(true);
		String encryptedPassword = passwordEncoder.encode(user.getPassword());
		user.setPassword(encryptedPassword);
		for (Authority ur : user.getAuthorities()) {
			authorityRepository.save(ur);
		}
		return userRepository.save(user);
	}

	@Transactional
	public void createAccountActivationTokenForUser(AppUser user, String token) {
		AccountActivationToken myToken = new AccountActivationToken(token, user);
		accountActivationTokenRepository.save(myToken);
	}

	@Transactional
	public boolean validateAccountActivationToken(long id, String token) {
		AccountActivationToken passToken = accountActivationTokenRepository.findByToken(token);
		if ((passToken == null) || (passToken.getUser().getId() != id)) {
			return false;
		}
		AppUser tokenUser = passToken.getUser();
		tokenUser.setEnabled(true);
		userRepository.save(tokenUser);
		accountActivationTokenRepository.delete(passToken);
		return true;
	}

	@Transactional
	public boolean toggleEnableUser(long userId) {
		AppUser user = userRepository.findById(userId).get();
		user.setEnabled(!user.isEnabled());
		userRepository.save(user);
		return user.isEnabled();
	}

	@Transactional
	public void saveNewUserWithStandardRole(AppUser user) {
		Set<Authority> userRoles = new HashSet<>();
		Authority userRoleAuthority = authorityRepository.findByAuthority("ROLE_USER");
		userRoles.add(userRoleAuthority);
		this.createUser(user, userRoles);
	}

	@Transactional
	public Page<UserSimplified> listUsers(Pageable pageable) {
		return userRepository.findAllBy(pageable);
	}

	@Transactional
	public UserSimplified findSimplifiedByName(String name) {
		return userRepository.findSimplifiedByName(name);
	}

	@Transactional
	public void updateUserRoles(AppUser appUser, List<Long> authorityIds) {
		Iterable<Authority> authorities = authorityRepository.findAllById(authorityIds);
		List<Authority> authoritiesList = new ArrayList<>();
		authorities.forEach(authoritiesList::add);
		appUser.setAuthorities(authoritiesList);
		userRepository.save(appUser);
	}

	@Transactional
	public void deleteUser(Long userId) {
		userRepository.deleteById(userId);
	}

	@Transactional
	private void checkIfPhoneNumberExistsInDb(String phoneNumber, List<String> errorMessages) {
		AppUser found = userRepository.findByUserDataPhone(phoneNumber);
		if (found != null) {
			errorMessages.add(Utils.phoneNumberExistsMsg);
		}
	}

	@Transactional
	private void checkIfEmailExistsInDb(String email, List<String> errorMessages) {
		AppUser found = userRepository.findByUserDataEmail(email);
		if (found != null) {
			errorMessages.add(Utils.emailExistsMsg);
		}
	}

	@Transactional
	private void checkIfUserNameExistsInDb(AppUser user, List<String> errorMessages) {
		AppUser found = userRepository.findByName(user.getName());
		if (found != null) {
			errorMessages.add(Utils.userNameExistsMsg);
		}
	}

	private boolean isTokenExpired(PasswordResetToken passToken) {
		Calendar cal = Calendar.getInstance();
		return (passToken.getExpiryDate().getTime() - cal.getTime().getTime()) <= 0;
	}

	private boolean checkPasswordsAreEqual(String password, String passwordConfirmation) {
		return password != null && password.equals(passwordConfirmation);
	}
}
