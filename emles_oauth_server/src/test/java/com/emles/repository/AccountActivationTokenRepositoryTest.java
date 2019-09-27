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

import com.emles.model.AccountActivationToken;
import com.emles.model.AppUser;

@RunWith(SpringRunner.class)
@DataJpaTest
@AutoConfigureTestDatabase(connection = EmbeddedDatabaseConnection.H2)
@TestPropertySource("classpath:application-repository-test.properties")
public class AccountActivationTokenRepositoryTest {

	@Autowired
	private AccountActivationTokenRepository accountActivationTokenRepository;

	@Autowired
	private AppUserRepository appUserRepository;

	@Autowired
	private TestEntityManager entityManager;

	private AccountActivationToken accountActivationToken;

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

		accountActivationToken = new AccountActivationToken();
		accountActivationToken.setToken("abcd");
		accountActivationToken.setUser(user);
	}

	@Test
	public void testPersistenceOfTokenSuccess() {
		entityManager.persist(accountActivationToken);
		AccountActivationToken found = accountActivationTokenRepository.findByToken(accountActivationToken.getToken());
		assertEquals(found.getToken(), accountActivationToken.getToken());
		assertEquals(found.getUser().getName(), user.getName());
	}

	@Test(expected = ConstraintViolationException.class)
	public void testPersistenceOfTokenFailsWhenTokenIsNull() {
		accountActivationToken.setToken(null);
		entityManager.persist(accountActivationToken);
	}

	@Test(expected = ConstraintViolationException.class)
	public void testPersistenceOfTokenFailsWhenUserIsNull() {
		accountActivationToken.setUser(null);
		entityManager.persist(accountActivationToken);
	}
}
