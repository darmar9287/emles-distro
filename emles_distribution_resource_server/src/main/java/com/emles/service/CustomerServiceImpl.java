package com.emles.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.Errors;

import com.emles.model.Customer;
import com.emles.repository.CustomerRepository;
import com.emles.utils.Utils;

@Service
public class CustomerServiceImpl implements CustomerService {

	@Autowired
	private CustomerRepository customerRepository;
	
	@Override
	@Transactional
	public Customer saveCustomer(Customer customer, Errors errors, List<String> errorMessages) {
		checkOtherValidationErrors(errors, errorMessages);
		if (!errorMessages.isEmpty()) {
			return null;
		}
		validateUniqueValuesForCustomer(customer, errorMessages);
		if (!errorMessages.isEmpty()) {
			return null;
		}
		return customerRepository.save(customer);
	}

	@Override
	@Transactional
	public Optional<Customer> findCustomerById(long customerId) {
		return customerRepository.findById(customerId);
	}

	@Override
	@Transactional
	public Customer findCustomerByEmailAddress(String emailAddress) {
		return customerRepository.findByCustomerAddress(emailAddress);
	}

	@Override
	@Transactional
	public Customer findCustomerByPhoneNumber(String phoneNumber) {
		return customerRepository.findByCustomerPhone(phoneNumber);
	}

	@Override
	@Transactional
	public Page<Customer> findCustomersByName(String searchTerm, Pageable pageable) {
		return customerRepository.findByName(searchTerm, pageable);
	}

	@Override
	@Transactional
	public Page<Customer> listCustomers(Pageable pageable) {
		return customerRepository.findAll(pageable);
	}

	@Override
	@Transactional
	public void deleteCustomer(long customerId) {
		customerRepository.deleteById(customerId);
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
	public void validateUniqueValuesForCustomer(Customer customer, List<String> errorMessages) {
		checkIfEmailExistsInDb(customer.getCustomerAddress(), errorMessages);
		checkIfPhoneNumberExistsInDb(customer.getCustomerPhone(), errorMessages);
	}
	
	@Transactional
	private void checkIfPhoneNumberExistsInDb(String phoneNumber, List<String> errorMessages) {
		Customer found = customerRepository.findByCustomerPhone(phoneNumber);
		if (found != null) {
			errorMessages.add(Utils.phoneNumberExistsMsg);
		}
	}

	@Transactional
	private void checkIfEmailExistsInDb(String email, List<String> errorMessages) {
		Customer found = customerRepository.findByCustomerAddress(email);
		if (found != null) {
			errorMessages.add(Utils.emailExistsMsg);
		}
	}
}
