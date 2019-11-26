package com.emles.service;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.validation.Errors;

import com.emles.model.Customer;

public interface CustomerService {

	public void saveCustomer(Customer customer, Errors errors, List<String> errorMessages);
	
	public Optional<Customer> findCustomerById(long customerId);
	
	public Customer findCustomerByEmailAddress(String emailAddress);
	
	public Customer findCustomerByPhoneNumber(String phoneNumber);
	
	public Page<Customer> findCustomersByName(String searchTerm, Pageable pageable);
	
	public Page<Customer> listCustomers(Pageable pageable);
	
	public void deleteCustomer(long customerId);
	
	public void checkOtherValidationErrors(Errors errors, List<String> errorMessages);
	
	public void validateUniqueValuesForCustomer(Customer customer, List<String> errorMessages);
}
