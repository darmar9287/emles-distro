package com.emles.repository;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.time.Instant;
import java.util.Arrays;
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
}
