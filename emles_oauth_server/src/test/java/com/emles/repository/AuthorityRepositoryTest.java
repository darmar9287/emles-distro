package com.emles.repository;

import static org.junit.Assert.assertEquals;

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

import com.emles.model.Authority;

@RunWith(SpringRunner.class)
@DataJpaTest
@AutoConfigureTestDatabase(connection = EmbeddedDatabaseConnection.H2)
@TestPropertySource("classpath:application-repository-test.properties")
public class AuthorityRepositoryTest {

	@Autowired
	private AuthorityRepository authorityRepository;

	@Autowired
	private TestEntityManager entityManager;

	private Authority authority;

	@Before
	public void setUp() {
		authority = new Authority();
		authority.setAuthority("ROLE_USER");
	}

	@Test
	public void testPersistenceOfAuthoritySuccess() {
		entityManager.persist(authority);
		Authority found = authorityRepository.findByAuthority(authority.getAuthority());
		assertEquals(found.getAuthority(), authority.getAuthority());
	}

	@Test(expected = ConstraintViolationException.class)
	public void testPersistenceOfAuthorityFailsWhenAuthorityNameIsNull() {
		authority.setAuthority(null);
		entityManager.persist(authority);
	}
}
