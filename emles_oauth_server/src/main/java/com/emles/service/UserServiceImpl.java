package com.emles.service;

import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.Errors;

import com.emles.model.AppUser;
import com.emles.model.PasswordResetToken;
import com.emles.model.Passwords;
import com.emles.model.UserPasswords;
import com.emles.repository.AppUserRepository;
import com.emles.repository.PasswordTokenRepository;
import com.emles.utils.Utils;

@Service
public class UserServiceImpl implements UserService {

	@Autowired
	private AppUserRepository userRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private PasswordTokenRepository passwordTokenRepository;

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
		return userRepository.findByEmail(email);
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

	private boolean isTokenExpired(PasswordResetToken passToken) {
		Calendar cal = Calendar.getInstance();
		return (passToken.getExpiryDate().getTime() - cal.getTime().getTime()) <= 0;
	}

	private boolean checkPasswordsAreEqual(String password, String passwordConfirmation) {
		return password.equals(passwordConfirmation);
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
	public void updateUserPassword(AppUser signedIn, UserPasswords passwords) {
		String encryptedPassword = passwordEncoder.encode(passwords.getNewPassword());
		signedIn.setPassword(encryptedPassword);
		userRepository.save(signedIn);
		
	}
}
