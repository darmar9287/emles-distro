package com.emles.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

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
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.validation.Errors;
import org.springframework.validation.ObjectError;

import com.emles.model.Customer;
import com.emles.repository.CustomerRepository;
import com.emles.utils.Utils;

@RunWith(SpringRunner.class)
public class CustomerServiceTest {

	@TestConfiguration
	static class CustomerServiceContextConfiguration {
		@Bean
		public CustomerService customerService() {
			return new CustomerServiceImpl();
		}
	}
	
	@Autowired
	private CustomerService customerService;
	
	@MockBean
	private CustomerRepository customerRepository;
	
	@Mock
	private Errors errors;
	
	@Mock
	private Customer customer;
	
	private String address = "test@test.com";
	
	private String customerName = "Marek Polny";
	
	private String customerPhone = "997997997";
	
	private long customerId = 1L;
	
	@Before
	public void setUp() {
		when(customer.getCustomerAddress()).thenReturn(address);
		when(customer.getCustomerName()).thenReturn(customerName);
		when(customer.getCustomerPhone()).thenReturn(customerPhone);
		when(customer.getCustomerId()).thenReturn(customerId);
	}
	
	@Test
	public void testAddCustomerShouldNotCheckUniqueValuesWhenOtherValidationErrorsArePresent() {
		List<String> errorMessages = new ArrayList<>();
		ObjectError oe = new ObjectError("email", Utils.emailExistsMsg);
		List<ObjectError> validationErrors = Arrays.asList(oe);

		when(errors.hasErrors()).thenReturn(true);
		when(errors.getAllErrors()).thenReturn(validationErrors);
		
		customerService.saveCustomer(customer, errors, errorMessages);
		
		verify(errors, times(1)).hasErrors();
		verify(errors, times(1)).getAllErrors();
		verify(customer, times(0)).getCustomerPhone();
		verify(customer, times(0)).getCustomerAddress();
		verify(customerRepository, times(0)).findByCustomerAddress(Mockito.anyString());
		verify(customerRepository, times(0)).findByCustomerPhone(Mockito.anyString());
		verify(customerRepository, times(0)).save(Mockito.any());
		
		assertEquals(errorMessages.size(), 1);
		assertTrue(errorMessages.contains(Utils.emailExistsMsg));
	}
	
	@Test
	public void testAddCustomerShouldCheckUniqueValuesWhenOtherValidationErrorsAreNotPresent() {
		List<String> errorMessages = new ArrayList<>();
		
		when(errors.hasErrors()).thenReturn(false);
		when(customerRepository.findByCustomerAddress(address)).thenReturn(customer);
		when(customerRepository.findByCustomerPhone(customerPhone)).thenReturn(customer);
		
		customerService.saveCustomer(customer, errors, errorMessages);
		
		verify(errors, times(1)).hasErrors();
		verify(errors, times(0)).getAllErrors();
		verify(customer, times(1)).getCustomerPhone();
		verify(customer, times(1)).getCustomerAddress();
		verify(customerRepository, times(1)).findByCustomerAddress(Mockito.anyString());
		verify(customerRepository, times(1)).findByCustomerPhone(Mockito.anyString());
		verify(customerRepository, times(0)).save(Mockito.any());
		
		assertEquals(errorMessages.size(), 2);
		assertTrue(errorMessages.contains(Utils.emailExistsMsg));
		assertTrue(errorMessages.contains(Utils.phoneNumberExistsMsg));
	}
	
	@Test
	public void testAddCustomerShouldCallSaveWhenNoErrorsArePresent() {
		List<String> errorMessages = new ArrayList<>();
		
		when(errors.hasErrors()).thenReturn(false);
		when(customerRepository.findByCustomerAddress(address)).thenReturn(null);
		when(customerRepository.findByCustomerPhone(customerPhone)).thenReturn(null);
		
		customerService.saveCustomer(customer, errors, errorMessages);
		
		verify(errors, times(1)).hasErrors();
		verify(errors, times(0)).getAllErrors();
		verify(customer, times(1)).getCustomerPhone();
		verify(customer, times(1)).getCustomerAddress();
		verify(customerRepository, times(1)).findByCustomerAddress(Mockito.anyString());
		verify(customerRepository, times(1)).findByCustomerPhone(Mockito.anyString());
		verify(customerRepository, times(1)).save(customer);
		
		assertEquals(errorMessages.size(), 0);
	}
	
	@Test
	public void testFindCustomerById() {
		Optional<Customer> customerOpt = Optional.of(customer);
		when(customerRepository.findById(customerId)).thenReturn(customerOpt);
		
		customerService.findCustomerById(customerId);
		
		verify(customerRepository, times(1)).findById(customerId);
	}
	
	@Test
	public void testFindCustomerByEmailAddress() {
		when(customerRepository.findByCustomerAddress(address)).thenReturn(customer);
		
		customerService.findCustomerByEmailAddress(address);
		
		verify(customerRepository, times(1)).findByCustomerAddress(address);
	}
	
	@Test
	public void testFindCustomerByPhoneNumber() {
		when(customerRepository.findByCustomerPhone(customerPhone)).thenReturn(customer);
		
		customerService.findCustomerByPhoneNumber(customerPhone);
		
		verify(customerRepository, times(1)).findByCustomerPhone(customerPhone);
	}
	
	@Test
	public void testFindCustomerByName() {
		Pageable pageable = PageRequest.of(0, 1);
		String searchTerm = "Kath";
	
		customerService.findCustomersByName(searchTerm, pageable);
		verify(customerRepository, times(1)).findByName(searchTerm, pageable);
	}
	
	@Test
	public void testListCustomers() {
		Pageable pageable = PageRequest.of(0, 1);
		customerService.listCustomers(pageable);
		verify(customerRepository, times(1)).findAll(pageable);
	}
	
	@Test
	public void testDeleteCustomer() {
		customerService.deleteCustomer(customerId);
		verify(customerRepository, times(1)).deleteById(customerId);
	}
}
