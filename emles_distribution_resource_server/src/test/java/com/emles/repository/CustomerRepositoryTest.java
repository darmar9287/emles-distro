package com.emles.repository;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Optional;
import java.util.stream.IntStream;

import javax.validation.ConstraintViolationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.EmbeddedDatabaseConnection;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.emles.model.Customer;

@RunWith(SpringRunner.class)
@DataJpaTest
@AutoConfigureTestDatabase(connection = EmbeddedDatabaseConnection.H2)
@TestPropertySource("classpath:application-repository-test.properties")
public class CustomerRepositoryTest {

	@Autowired
	private CustomerRepository customerRepository;
	
	private Customer customer;
	
	private String[] names = {
		"Marie Scott",
		"Russell Sanchez",
		"Daniel Smith",
		"Kathy Carter",
		"Frances Perez",
		"Kathleen Morris",
		"Katherine Russell",
		"Jason Powell",
		"Stephanie Phillips",
		"James Reed"	
	};
	
	@Before
	public void setUp() {
		IntStream.rangeClosed(1, 10).forEach(i -> {
			Customer c = new Customer();
			c.setCustomerAddress(String.format("customer%d@test.com", i));
			c.setCustomerName(names[i - 1]);
			c.setCustomerPhone(String.format("7008009%d", i + 10));
			customerRepository.save(c);
		});
		
		customer = new Customer();
		customer.setCustomerAddress("test44@test.com");
		customer.setCustomerPhone("222222222");
		customer.setCustomerName("cutomer second");
	}
	
	@Test
	public void testPaginationOfCustomers() {
		Page<Customer> result = customerRepository.findByName("Kath", PageRequest.of(0, 10));
		assertEquals(3, result.getTotalElements());
	}
	
	@Test
	public void testFindCustomerByPhone() {
		Customer customer = customerRepository.findByCustomerPhone("700800911");
		assertNotNull(customer);
		customer = customerRepository.findByCustomerPhone("111111111");
		assertNull(customer);
	}
	
	@Test
	public void testFindCustomerByEmailAddress() {
		Customer customer = customerRepository.findByCustomerAddress("customer1@test.com");
		assertNotNull(customer);
		customer = customerRepository.findByCustomerAddress("test@testing.com");
		assertNull(customer);
	}
	
	@Test(expected = ConstraintViolationException.class)
	public void testCreateCustomerWithForbiddenCharsInUserNameShouldFail() {
		customer.setCustomerName(" ttt__11223*&*^^% {}{);:,,.'';[");
		customerRepository.save(customer);
	}
	
	@Test(expected = ConstraintViolationException.class)
	public void testCreateCustomerWithTooLongUserNameShouldFail() {
		String s = "ABCDEFGHIJKLMNOPRSTUWYXZ abcdefghijklmnoprstuwyxz";
		StringBuilder sb = new StringBuilder();
		IntStream.range(0, 10).forEach(i -> {
			sb.append(s);
		});
		String tooLongName = sb.toString();
		customer.setCustomerName(tooLongName);
		customerRepository.save(customer);
	}
	
	@Test(expected = ConstraintViolationException.class)
	public void testCreateCustomerWithTooShortUserNameShouldFail() {
		customer.setCustomerName("A");
		customerRepository.save(customer);
	}
	
	@Test(expected = ConstraintViolationException.class)
	public void testCreateCustomerWithNullUserNameShouldFail() {
		customer.setCustomerName(null);
		customerRepository.save(customer);
	}
	
	@Test(expected = ConstraintViolationException.class)
	public void testCreateCustomerWithInvalidEmailAddressShouldFail() {
		customer.setCustomerAddress("test.com");
		customerRepository.save(customer);
	}
	
	@Test(expected = ConstraintViolationException.class)
	public void testCreateCustomerWithNullEmailAddressShouldFail() {
		customer.setCustomerAddress(null);
		customerRepository.save(customer);
	}
	
	@Test(expected = DataIntegrityViolationException.class)
	public void testCreateCustomerWithExistingEmailAddressShouldFail() {
		customer.setCustomerAddress("customer1@test.com");
		customerRepository.save(customer);
	}
	
	@Test(expected = ConstraintViolationException.class)
	public void testCreateCustomerWithInvalidPhoneShouldFail() {
		customer.setCustomerPhone("1234455557");
		customerRepository.save(customer);
	}
	
	@Test(expected = ConstraintViolationException.class)
	public void testCreateCustomerWithNullPhoneShouldFail() {
		customer.setCustomerPhone(null);
		customerRepository.save(customer);
	}
	
	@Test(expected = DataIntegrityViolationException.class)
	public void testCreateCustomerWithExistingPhoneShouldFail() {
		customer.setCustomerPhone("700800911");
		customerRepository.save(customer);
	}
	
	@Test
	public void testUpdateCustomer() {
		Customer customer = customerRepository.findByCustomerPhone("700800911");
		long customerId = customer.getCustomerId();
		customer.setCustomerAddress("marekpolny@test.com");
		customer.setCustomerName("Marek Polny");
		customer.setCustomerPhone("997997997");
		customerRepository.save(customer);
		
		Optional<Customer> foundOpt = customerRepository.findById(customerId);
		Customer found = foundOpt.get();
		
		assertTrue(foundOpt.isPresent());
		assertTrue(found.getCustomerAddress().equals(customer.getCustomerAddress()));
		assertTrue(found.getCustomerName().equals(customer.getCustomerName()));
		assertTrue(found.getCustomerPhone().equals(customer.getCustomerPhone()));
	}
	
	@Test
	public void testDeleteCustomer() {
		Customer customer = customerRepository.findByCustomerPhone("700800911");
		long customerId = customer.getCustomerId();
		customerRepository.delete(customer);
		Optional<Customer> foundOpt = customerRepository.findById(customerId);
		assertFalse(foundOpt.isPresent());
	}
}
