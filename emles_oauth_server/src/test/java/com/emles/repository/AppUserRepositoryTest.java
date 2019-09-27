package com.emles.repository;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;

import javax.persistence.PersistenceException;
import javax.validation.ConstraintViolationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.EmbeddedDatabaseConnection;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.emles.model.AppUser;
import com.emles.model.Authority;

@RunWith(SpringRunner.class)
@DataJpaTest
@AutoConfigureTestDatabase(connection = EmbeddedDatabaseConnection.H2)
@TestPropertySource("classpath:application-repository-test.properties")
public class AppUserRepositoryTest {

	@Autowired
	private AppUserRepository appUserRepository;

	@Autowired
	private AuthorityRepository authorityRepository;

	@Autowired
	private TestEntityManager entityManager;

	private AppUser user;

	private AppUser secondUser;

	@Before
	public void setUp() {
		Authority userAuthority = new Authority();
		userAuthority.setAuthority("ROLE_USER");
		authorityRepository.save(userAuthority);

		String newUserPassword = "h4$h3dPa$$";
		user = new AppUser();
		user.setEmail("newuser@emles.com");
		user.setName("newuser");
		user.setPassword(newUserPassword);
		user.setPasswordConfirmation(newUserPassword);
		user.setPhone("600600666");
		user.setLastPasswordResetDate(Date.from(Instant.now()));
		user.setAuthorities(Arrays.asList(userAuthority));
		user.setEnabled(true);

		secondUser = new AppUser();
		secondUser.setEmail("new_second_user@emles.com");
		secondUser.setName("new_second_user");
		secondUser.setPassword(newUserPassword);
		secondUser.setPasswordConfirmation(newUserPassword);
		secondUser.setPhone("700600666");
		secondUser.setLastPasswordResetDate(Date.from(Instant.now()));
		secondUser.setAuthorities(Arrays.asList(userAuthority));
		secondUser.setEnabled(true);
	}

	@Test
	public void testCreateUserSuccess() {
		entityManager.persist(user);
		AppUser found = appUserRepository.findByName(user.getName());
		assertNotNull(found);
		assertEquals(found.getName(), user.getName());
		assertEquals(found.getAuthorities().size(), 1);
		assertEquals(found.getAuthorities().get(0).getAuthority(), "ROLE_USER");
		assertEquals(found.getEmail(), user.getEmail());
		assertEquals(found.getPhone(), user.getPhone());
		assertTrue(found.isEnabled());
	}

	@Test(expected = ConstraintViolationException.class)
	public void testCreateUserWithTooShortNameFails() {
		user.setName("abc");
		entityManager.persist(user);
	}

	@Test(expected = ConstraintViolationException.class)
	public void testCreateUserWithTooLongNameFails() {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 5; i++) {
			sb.append("ABCDEFGHIJKLMNOPRSTQUWYXZ");
		}
		String tooLongName = sb.toString();
		user.setName(tooLongName);
		entityManager.persist(user);
	}

	@Test(expected = ConstraintViolationException.class)
	public void testCreateUserWithInvalidNameCharactersFails() {
		String invalidCharsName = "&*&@@#,.'\\";
		user.setName(invalidCharsName);
		entityManager.persist(user);
	}

	@Test(expected = PersistenceException.class)
	public void testCreateUserWithExistingNameFails() {
		entityManager.persist(user);
		secondUser.setName(user.getName());
		entityManager.persist(secondUser);
	}

	@Test(expected = ConstraintViolationException.class)
	public void testCreateUserWithInvalidPasswordFails() {
		String invalidPassword = "abcdefgh";
		user.setPassword(invalidPassword);
		entityManager.persist(user);
	}

	@Test(expected = ConstraintViolationException.class)
	public void testCreateUserWithInvalidPasswordConfirmationFails() {
		String invalidPassword = "abcdefgh";
		user.setPasswordConfirmation(invalidPassword);
		entityManager.persist(user);
	}

	@Test(expected = ConstraintViolationException.class)
	public void testCreateUserWithTooShortPasswordFails() {
		String invalidPassword = "abcd";
		user.setPassword(invalidPassword);
		entityManager.persist(user);
	}

	@Test(expected = ConstraintViolationException.class)
	public void testCreateUserWithTooLongPasswordFails() {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 5; i++) {
			sb.append("ABCDEFGHIJKLMNOPRSTQUWYXZabcd123&^%$#_");
		}
		String invalidPassword = sb.toString();
		user.setPassword(invalidPassword);
		entityManager.persist(user);
	}

	@Test(expected = ConstraintViolationException.class)
	public void testCreateUserWithInvalidEmailFails() {
		String invalidEmail = "testdddd.com";
		user.setEmail(invalidEmail);
		entityManager.persist(user);
	}

	@Test(expected = PersistenceException.class)
	public void testCreateUserWithExistingEmailFails() {
		entityManager.persist(user);
		secondUser.setEmail(user.getEmail());
		entityManager.persist(secondUser);
	}

	@Test(expected = ConstraintViolationException.class)
	public void testCreateUserWithInvalidPhoneFails() {
		user.setPhone("123-fdfbd");
		entityManager.persist(user);
	}

	@Test(expected = PersistenceException.class)
	public void testCreateUserWithExistingPhoneFails() {
		entityManager.persist(user);
		secondUser.setPhone(user.getPhone());
		entityManager.persist(secondUser);
	}

	@Test(expected = PersistenceException.class)
	public void testCreateUserFailsWhenLastPasswordResetDateIsNull() {
		user.setLastPasswordResetDate(null);
		entityManager.persist(user);
	}
}
