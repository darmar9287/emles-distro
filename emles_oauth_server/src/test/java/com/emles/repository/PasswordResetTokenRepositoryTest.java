package com.emles.repository;

import static org.junit.Assert.assertEquals;

import java.time.Instant;
import java.util.Date;

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
import com.emles.model.PasswordResetToken;

@RunWith(SpringRunner.class)
@DataJpaTest
@AutoConfigureTestDatabase(connection = EmbeddedDatabaseConnection.H2)
@TestPropertySource("classpath:application-repository-test.properties")
public class PasswordResetTokenRepositoryTest {

	@Autowired
	private PasswordTokenRepository passwordTokenRepository;

	@Autowired
	private AppUserRepository appUserRepository;

	@Autowired
	private TestEntityManager entityManager;

	private PasswordResetToken passwordResetToken;

	private AppUser user;

	@Before
	public void setUp() {
		String newUserPassword = "h4$h3dPa$$";
		user = new AppUser();
		user.setEmail("newuser@emles.com");
		user.setName("newuser");
		user.setPassword(newUserPassword);
		user.setPasswordConfirmation(newUserPassword);
		user.setPhone("600600666");
		user.setLastPasswordResetDate(Date.from(Instant.now()));
		user.setEnabled(true);
		appUserRepository.save(user);

		passwordResetToken = new PasswordResetToken();
		passwordResetToken.setToken("abcd");
		passwordResetToken.setUser(user);
		passwordResetToken.setExpiryDate(Date.from(Instant.now()));
	}

	@Test
	public void testPersistenceOfTokenSuccess() {
		entityManager.persist(passwordResetToken);
		PasswordResetToken found = passwordTokenRepository.findByToken(passwordResetToken.getToken());
		assertEquals(found.getToken(), passwordResetToken.getToken());
		assertEquals(found.getUser().getName(), user.getName());
	}

	@Test(expected = ConstraintViolationException.class)
	public void testPersistenceOfTokenFailsWhenTokenIsNull() {
		passwordResetToken.setToken(null);
		entityManager.persist(passwordResetToken);
	}

	@Test(expected = ConstraintViolationException.class)
	public void testPersistenceOfTokenFailsWhenUserIsNull() {
		passwordResetToken.setUser(null);
		entityManager.persist(passwordResetToken);
	}

	@Test(expected = ConstraintViolationException.class)
	public void testPersistenceOfTokenFailsWhenExpiryDateIsNull() {
		passwordResetToken.setExpiryDate(null);
		entityManager.persist(passwordResetToken);
	}
}
