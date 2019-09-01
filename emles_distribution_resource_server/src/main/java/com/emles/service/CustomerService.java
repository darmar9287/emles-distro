package com.emles.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import com.emles.model.Customer;
import com.emles.repository.CustomerRepository;

@Service
public class CustomerService {
	
	@Autowired
	CustomerRepository customerRepository;

	public Page<Customer> showCustomers(Pageable pageable) {
		return customerRepository.findAll(pageable);
	}
	
	public Optional<Customer> findCustomerById(Long customerId) {
		return customerRepository.findById(customerId);
	}
}
