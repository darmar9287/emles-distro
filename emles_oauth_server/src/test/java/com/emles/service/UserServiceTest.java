package com.emles.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.validation.Errors;
import org.springframework.validation.ObjectError;

import com.emles.model.AccountActivationToken;
import com.emles.model.AppUser;
import com.emles.model.Authority;
import com.emles.model.PasswordResetToken;
import com.emles.model.Passwords;
import com.emles.model.UserData;
import com.emles.repository.AccountActivationTokenRepository;
import com.emles.repository.AppUserRepository;
import com.emles.repository.AuthorityRepository;
import com.emles.repository.PasswordTokenRepository;
import com.emles.utils.Utils;

@RunWith(SpringRunner.class)
public class UserServiceTest {

	@TestConfiguration
	static class UserServiceContextConfiguration {
		@Bean
		public UserService userService() {
			return new UserServiceImpl();
		}
	}

	@Autowired
	private UserService userService;

	@MockBean
	private AppUserRepository appUserRepository;

	@MockBean
	private PasswordEncoder passwordEncoder;

	@MockBean
	private PasswordTokenRepository passwordTokenRepository;

	@MockBean
	private AuthorityRepository authorityRepository;

	@MockBean
	private AccountActivationTokenRepository accountActivationTokenRepository;

	@Mock
	private AppUser user;

	@Mock
	private PasswordResetToken resetToken;

	@Mock
	private Errors errors;

	@Mock
	private AccountActivationToken activationToken;

	@Before
	public void setUp() {
		UserData userData = new UserData();
		userData.setEmail("test@test.com");
		userData.setPhone("123456789");

		when(user.getId()).thenReturn(1L);
		when(user.getName()).thenReturn("user");
		when(user.getPhone()).thenReturn("123456789");
		when(user.getEmail()).thenReturn("test@test.com");
		when(user.getPassword()).thenReturn("h4$H3dP4$s");
		when(user.getPasswordConfirmation()).thenReturn("h4$H3dP4$s");
		when(user.getUserData()).thenReturn(userData);
		when(user.getAuthorities()).thenReturn(new ArrayList<Authority>());

		when(resetToken.getUser()).thenReturn(user);
		when(resetToken.getExpiryDate()).thenReturn(Date.from(Instant.now().plus(Duration.ofDays(2L))));

		when(activationToken.getUser()).thenReturn(user);
	}

	@Test
	public void testUserFindById() {
		Optional<AppUser> optionalValue = Optional.of(user);
		when(appUserRepository.findById(1L)).thenReturn(optionalValue);
		Optional<AppUser> found = userService.findById(1L);
		verify(appUserRepository, times(1)).findById(1L);
		assertTrue(found.isPresent());
	}

	@Test
	public void testUserFindByName() {
		String userName = "user";
		when(appUserRepository.findByName(userName)).thenReturn(user);
		AppUser found = userService.findByName(userName);
		verify(appUserRepository, times(1)).findByName(userName);
		assertEquals(found.getName(), user.getName());
	}

	@Test
	public void testUserFindByEmail() {
		String userEmail = "test@test.com";
		when(appUserRepository.findByUserDataEmail(userEmail)).thenReturn(user);
		AppUser found = userService.findByEmail(userEmail);
		verify(appUserRepository, times(1)).findByUserDataEmail(userEmail);
		assertEquals(found.getEmail(), user.getEmail());
	}

	@Test
	public void testCheckIfUsernameExistsReturnsTrueWhenNameExists() {
		String userName = "user";
		when(appUserRepository.findByName(userName)).thenReturn(user);
		assertTrue(userService.checkUsernameExists(userName));
		verify(appUserRepository, times(1)).findByName(userName);
	}

	@Test
	public void testCheckIfUsernameExistsReturnsFalseWhenNameDoesNotExist() {
		String userName = "user";
		when(appUserRepository.findByName(userName)).thenReturn(null);
		assertFalse(userService.checkUsernameExists(userName));
		verify(appUserRepository, times(1)).findByName(userName);
	}

	@Test
	public void testCreatePasswordResetTokenDeletesExistingToken() {
		String passwordTokenString = "abcd";
		when(passwordTokenRepository.findByUser(user)).thenReturn(resetToken);

		userService.createPasswordResetTokenForUser(user, passwordTokenString);

		verify(passwordTokenRepository, times(1)).delete(resetToken);
		verify(user, times(1)).setLastPasswordResetDate(Mockito.any());
		verify(passwordTokenRepository, times(1)).save(Mockito.any());
		verify(appUserRepository, times(1)).save(Mockito.any());
	}

	@Test
	public void testCreatePasswordResetTokenDoesNotDeleteExistingToken() {
		String passwordTokenString = "abcd";
		when(passwordTokenRepository.findByUser(user)).thenReturn(null);

		userService.createPasswordResetTokenForUser(user, passwordTokenString);

		verify(passwordTokenRepository, times(0)).delete(resetToken);
		verify(user, times(1)).setLastPasswordResetDate(Mockito.any());
		verify(passwordTokenRepository, times(1)).save(Mockito.any());
		verify(appUserRepository, times(1)).save(Mockito.any());
	}

	@Test
	public void testCheckEqualityOfPasswordsAddsErrorMessageWhenTheyAreNotEqual() {
		List<String> errorMessages = new ArrayList<>();

		when(user.getPasswordConfirmation()).thenReturn("abcd");

		userService.checkEqualityOfPasswords(user, errorMessages);

		verify(user, times(1)).getPassword();
		verify(user, times(1)).getPasswordConfirmation();
		assertEquals(errorMessages.size(), 1);
	}

	@Test
	public void testCheckEqualityOfPasswordsDoesNotAddErrorMessageWhenTheyAreEqual() {
		List<String> errorMessages = new ArrayList<>();

		userService.checkEqualityOfPasswords(user, errorMessages);

		verify(user, times(1)).getPassword();
		verify(user, times(1)).getPasswordConfirmation();
		assertEquals(errorMessages.size(), 0);
	}

	@Test
	public void testValidatePasswordResetTokenReturnsNullWhenTokenIsValid() {
		String tokenString = "abcd";

		when(passwordTokenRepository.findByToken(tokenString)).thenReturn(resetToken);

		assertNull(userService.validatePasswordResetToken(1L, tokenString));

		verify(resetToken, times(1)).getUser();
		verify(resetToken, times(1)).getExpiryDate();
		verify(passwordTokenRepository, times(1)).findByToken(tokenString);
		verify(passwordTokenRepository, times(0)).delete(resetToken);
	}

	@Test
	public void testValidatePasswordResetTokenReturnsInvalidTokenWhenTokenIsNull() {
		String tokenString = "abcd";

		when(passwordTokenRepository.findByToken(tokenString)).thenReturn(null);

		assertEquals(userService.validatePasswordResetToken(1L, tokenString), "invalidToken");

		verify(resetToken, times(0)).getUser();
		verify(resetToken, times(0)).getExpiryDate();
		verify(passwordTokenRepository, times(1)).findByToken(tokenString);
		verify(passwordTokenRepository, times(0)).delete(resetToken);
	}

	@Test
	public void testValidatePasswordResetTokenReturnsInvalidTokenWhenUserIdIsDifferent() {
		String tokenString = "abcd";

		when(passwordTokenRepository.findByToken(tokenString)).thenReturn(resetToken);

		assertEquals(userService.validatePasswordResetToken(2L, tokenString), "invalidToken");

		verify(resetToken, times(1)).getUser();
		verify(resetToken, times(0)).getExpiryDate();
		verify(passwordTokenRepository, times(1)).findByToken(tokenString);
		verify(passwordTokenRepository, times(0)).delete(resetToken);
	}

	@Test
	public void testValidatePasswordResetTokenReturnsExpiredTokenStringWhenTokenIsExpired() {
		String tokenString = "abcd";

		when(passwordTokenRepository.findByToken(tokenString)).thenReturn(resetToken);
		when(resetToken.getExpiryDate()).thenReturn(Date.from(Instant.now().minus(Duration.ofDays(10))));
		assertEquals(userService.validatePasswordResetToken(1L, tokenString), "expired");

		verify(resetToken, times(1)).getUser();
		verify(resetToken, times(1)).getExpiryDate();
		verify(passwordTokenRepository, times(1)).findByToken(tokenString);
		verify(passwordTokenRepository, times(1)).delete(resetToken);
	}

	@Test
	public void testUpdateUserPasswordWithResetToken() {
		Passwords passwords = new Passwords();
		passwords.setPassword("pass");
		passwords.setPasswordConfirmation("pass");
		String token = "abcd";

		when(user.getPassword()).thenReturn("pass");
		when(passwordEncoder.encode("pass")).thenReturn("pass");
		when(passwordTokenRepository.findByToken(token)).thenReturn(resetToken);

		userService.updateUserPasswordWithResetToken(user, passwords, token);

		verify(user, times(1)).setPasswords(passwords);
		verify(passwordEncoder, times(1)).encode("pass");
		verify(user, times(1)).setPassword(Mockito.anyString());
		verify(user, times(1)).setLastPasswordResetDate(Mockito.any());
		verify(appUserRepository, times(1)).save(user);
		verify(passwordTokenRepository, times(1)).findByToken(token);
		verify(passwordTokenRepository, times(1)).delete(Mockito.any());
	}

	@Test
	public void testUpdateUserData() {
		UserData userData = new UserData();
		userData.setEmail("test@test.com");
		userData.setPhone("999999999");

		userService.updateUserData(user, userData);

		verify(user, times(1)).setUserData(userData);
		verify(appUserRepository, times(1)).save(user);
	}

	@Test
	public void testValidateUniqueValuesForUserUpdatesErrorListWhenUserNameExists() {
		List<String> errorMessages = new ArrayList<>();

		when(appUserRepository.findByName("user")).thenReturn(user);
		when(appUserRepository.findByUserDataEmail("test@test.com")).thenReturn(null);
		when(appUserRepository.findByUserDataPhone("123456789")).thenReturn(null);

		userService.validateUniqueValuesForUser(user, errorMessages);

		verify(appUserRepository, times(1)).findByName("user");
		verify(appUserRepository, times(1)).findByUserDataEmail("test@test.com");
		verify(appUserRepository, times(1)).findByUserDataPhone("123456789");
		verify(user, times(1)).getName();
		verify(user, times(2)).getUserData();
		assertEquals(errorMessages.size(), 1);
		assertTrue(errorMessages.contains(Utils.userNameExistsMsg));
	}

	@Test
	public void testValidateUniqueValuesForUserUpdatesErrorListWhenUserEmailExists() {
		List<String> errorMessages = new ArrayList<>();

		when(appUserRepository.findByName("user")).thenReturn(null);
		when(appUserRepository.findByUserDataEmail("test@test.com")).thenReturn(user);
		when(appUserRepository.findByUserDataPhone("123456789")).thenReturn(null);

		userService.validateUniqueValuesForUser(user, errorMessages);

		verify(appUserRepository, times(1)).findByName("user");
		verify(appUserRepository, times(1)).findByUserDataEmail("test@test.com");
		verify(appUserRepository, times(1)).findByUserDataPhone("123456789");
		verify(user, times(1)).getName();
		verify(user, times(2)).getUserData();
		assertEquals(errorMessages.size(), 1);
		assertTrue(errorMessages.contains(Utils.emailExistsMsg));
	}

	@Test
	public void testValidateUniqueValuesForUserUpdatesErrorListWhenUserPhoneExists() {
		List<String> errorMessages = new ArrayList<>();

		when(appUserRepository.findByName("user")).thenReturn(null);
		when(appUserRepository.findByUserDataEmail("test@test.com")).thenReturn(null);
		when(appUserRepository.findByUserDataPhone("123456789")).thenReturn(user);

		userService.validateUniqueValuesForUser(user, errorMessages);

		verify(appUserRepository, times(1)).findByName("user");
		verify(appUserRepository, times(1)).findByUserDataEmail("test@test.com");
		verify(appUserRepository, times(1)).findByUserDataPhone("123456789");
		verify(user, times(1)).getName();
		verify(user, times(2)).getUserData();
		assertEquals(errorMessages.size(), 1);
		assertTrue(errorMessages.contains(Utils.phoneNumberExistsMsg));
	}

	@Test
	public void testCheckOtherValidationErrorsAddsToListElementsWhenErrorsIsNotEmpty() {
		List<String> errorMessages = new ArrayList<>();
		ObjectError oe = new ObjectError("name", Utils.emailExistsMsg);
		List<ObjectError> validationErrors = Arrays.asList(oe);

		when(errors.hasErrors()).thenReturn(true);
		when(errors.getAllErrors()).thenReturn(validationErrors);

		userService.checkOtherValidationErrors(errors, errorMessages);

		verify(errors, times(1)).hasErrors();
		verify(errors, times(1)).getAllErrors();
		assertEquals(errorMessages.size(), 1);
		assertTrue(errorMessages.contains(Utils.emailExistsMsg));
	}

	@Test
	public void testCheckIfOldPasswordMatchesAddsErrorMessageWhenItDoesNotMatch() {
		String oldPass = "oldPass";
		List<String> errorMessages = new ArrayList<>();

		when(passwordEncoder.matches(oldPass, user.getPassword())).thenReturn(false);

		userService.checkIfOldPasswordMatches(user, oldPass, errorMessages);

		assertTrue(errorMessages.contains(Utils.oldPasswordDoesNotMatch));
		assertEquals(errorMessages.size(), 1);
	}

	@Test
	public void testCheckIfOldPasswordMatchesDoesNotAddErrorMessageWhenItMatches() {
		String oldPass = "oldPass";
		List<String> errorMessages = new ArrayList<>();

		when(passwordEncoder.matches(oldPass, user.getPassword())).thenReturn(true);

		userService.checkIfOldPasswordMatches(user, oldPass, errorMessages);

		assertFalse(errorMessages.contains(Utils.oldPasswordDoesNotMatch));
		assertEquals(errorMessages.size(), 0);
	}

	@Test
	public void testUpdateUserPassword() {
		String newPass = "newPass";

		when(passwordEncoder.encode(newPass)).thenReturn("aaabbcc");

		userService.updateUserPassword(user, newPass);

		verify(passwordEncoder, times(1)).encode(newPass);
		verify(user, times(1)).setPassword(Mockito.anyString());
		verify(appUserRepository, times(1)).save(user);
	}

	@Test
	public void testValidateUniqueValuesForUserDataAddsErrorMessageWhenValuesExist() {
		List<String> errorMessages = new ArrayList<>();

		UserData userData = new UserData();
		userData.setEmail("test1@test.com");
		userData.setPhone("987654321");

		when(appUserRepository.findByUserDataPhone(Mockito.anyString())).thenReturn(user);
		when(appUserRepository.findByUserDataEmail(Mockito.anyString())).thenReturn(user);

		userService.validateUniqueValuesForUserData(userData, errorMessages, user);

		verify(appUserRepository, times(1)).findByUserDataPhone(Mockito.anyString());
		verify(appUserRepository, times(1)).findByUserDataEmail(Mockito.anyString());
		assertEquals(errorMessages.size(), 2);
		assertTrue(errorMessages.contains(Utils.phoneNumberExistsMsg));
		assertTrue(errorMessages.contains(Utils.emailExistsMsg));
	}

	@Test
	public void testValidateUniqueValuesForUserDataDoesNotCheckForExistenceOfDataWhenUserDataIsNotChanged() {
		List<String> errorMessages = new ArrayList<>();

		when(appUserRepository.findByUserDataPhone(Mockito.anyString())).thenReturn(user);
		when(appUserRepository.findByUserDataEmail(Mockito.anyString())).thenReturn(user);

		userService.validateUniqueValuesForUserData(user.getUserData(), errorMessages, user);

		verify(appUserRepository, times(0)).findByUserDataPhone(Mockito.anyString());
		verify(appUserRepository, times(0)).findByUserDataEmail(Mockito.anyString());
		assertEquals(errorMessages.size(), 0);
	}

	@Test
	public void testCreateUserWithRoles() {
		Set<Authority> roles = new HashSet<>();
		Authority authority = new Authority();
		authority.setAuthority("ROLE_USER");
		roles.add(authority);

		when(authorityRepository.save(Mockito.any())).thenReturn(authority);
		when(passwordEncoder.encode(Mockito.anyString())).thenReturn("aaabb");

		userService.createUser(user, roles);

		verify(user, times(1)).getPassword();
		verify(user, times(1)).setPassword(Mockito.anyString());
		verify(user, times(1)).setAuthorities(Mockito.any());
		verify(user, times(1)).setEnabled(false);
		verify(user, times(1)).setLastPasswordResetDate(Mockito.any());
		verify(user, times(1)).getAuthorities();
		verify(authorityRepository, times(1)).save(Mockito.any());
		verify(appUserRepository, times(1)).save(user);
	}

	@Test
	public void testCreateUser() {
		List<Authority> authorities = new ArrayList<>();
		Authority authority = new Authority();
		authority.setAuthority("ROLE_USER");
		authorities.add(authority);

		when(user.getAuthorities()).thenReturn(authorities);

		userService.createUser(user);

		verify(user, times(1)).getAuthorities();
		verify(user, times(1)).setEnabled(true);
		verify(authorityRepository, times(1)).save(Mockito.any());
		verify(appUserRepository, times(1)).save(user);
	}

	@Test
	public void testCreateAccountActivationTokenForUser() {
		String token = "abcd";

		userService.createAccountActivationTokenForUser(user, token);

		verify(accountActivationTokenRepository, times(1)).save(Mockito.any());
	}

	@Test
	public void testValidateAccountActivationTokenReturnsFalseWhenTokenIsNotFound() {
		String token = "abcd";
		long userId = 1L;
		when(accountActivationTokenRepository.findByToken(token)).thenReturn(null);

		assertFalse(userService.validateAccountActivationToken(userId, token));

		verify(accountActivationTokenRepository, times(1)).findByToken(token);
		verify(activationToken, times(0)).getUser();
		verify(user, times(0)).getId();
		verify(user, times(0)).setEnabled(true);
		verify(appUserRepository, times(0)).save(user);
		verify(accountActivationTokenRepository, times(0)).delete(activationToken);
	}

	@Test
	public void testValidateAccountActivationTokenReturnsFalseWhenUserIdIsDifferent() {
		String token = "abcd";
		long userId = 2L;
		when(accountActivationTokenRepository.findByToken(token)).thenReturn(activationToken);

		assertFalse(userService.validateAccountActivationToken(userId, token));

		verify(accountActivationTokenRepository, times(1)).findByToken(token);
		verify(activationToken, times(1)).getUser();
		verify(user, times(1)).getId();
		verify(user, times(0)).setEnabled(true);
		verify(appUserRepository, times(0)).save(user);
		verify(accountActivationTokenRepository, times(0)).delete(activationToken);
	}

	@Test
	public void testValidateAccountActivationTokenReturnsTrueWhenUserDataIsCorrect() {
		String token = "abcd";
		long userId = 1L;
		when(accountActivationTokenRepository.findByToken(token)).thenReturn(activationToken);

		assertTrue(userService.validateAccountActivationToken(userId, token));

		verify(accountActivationTokenRepository, times(1)).findByToken(token);
		verify(activationToken, times(2)).getUser();
		verify(user, times(1)).getId();
		verify(user, times(1)).setEnabled(true);
		verify(appUserRepository, times(1)).save(user);
		verify(accountActivationTokenRepository, times(1)).delete(activationToken);
	}

	@Test
	public void testToggleEnableUser() {
		long id = 1L;
		Optional<AppUser> userOpt = Optional.of(user);

		when(appUserRepository.findById(id)).thenReturn(userOpt);

		userService.toggleEnableUser(id);

		verify(appUserRepository, times(1)).findById(id);
		verify(user, times(2)).isEnabled();
		verify(user, times(1)).setEnabled(Mockito.anyBoolean());
		verify(appUserRepository, times(1)).save(user);
	}

	@Test
	public void testSaveNewUserWithStandardRole() {
		Authority authority = new Authority();
		authority.setAuthority("ROLE_USER");

		when(authorityRepository.findByAuthority("ROLE_USER")).thenReturn(authority);
		when(authorityRepository.save(Mockito.any())).thenReturn(authority);
		when(passwordEncoder.encode(Mockito.anyString())).thenReturn("aaabb");

		userService.saveNewUserWithStandardRole(user);

		verify(authorityRepository, times(1)).findByAuthority("ROLE_USER");
		verify(user, times(1)).getPassword();
		verify(user, times(1)).setPassword(Mockito.anyString());
		verify(user, times(1)).setAuthorities(Mockito.any());
		verify(user, times(1)).setEnabled(false);
		verify(user, times(1)).setLastPasswordResetDate(Mockito.any());
		verify(user, times(1)).getAuthorities();
		verify(authorityRepository, times(1)).save(Mockito.any());
		verify(appUserRepository, times(1)).save(user);
	}

	@SuppressWarnings("deprecation")
	@Test
	public void testListUsers() {
		Pageable pageable = new PageRequest(0, 1);
		userService.listUsers(pageable);
		verify(appUserRepository, times(1)).findAllBy(pageable);
	}

	@Test
	public void testFindSimplifiedByName() {
		String name = "name";
		userService.findSimplifiedByName(name);
		verify(appUserRepository, times(1)).findSimplifiedByName(name);
	}

	@Test
	public void testUpdateUserRoles() {
		List<Long> authorityIds = Arrays.asList(1L, 2L);
		List<Authority> authorities = new ArrayList<>();

		when(authorityRepository.findAllById(authorityIds)).thenReturn(authorities);

		userService.updateUserRoles(user, authorityIds);

		verify(authorityRepository, times(1)).findAllById(authorityIds);
		verify(user, times(1)).setAuthorities(Mockito.any());
		verify(appUserRepository, times(1)).save(user);
	}

	@Test
	public void testDeleteUser() {
		long userId = 1L;
		userService.deleteUser(userId);
		verify(appUserRepository, times(1)).deleteById(userId);
	}
}
