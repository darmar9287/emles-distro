package com.emles.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import com.emles.model.Customer;
import com.emles.service.CustomerService;

@RestController
@RequestMapping(value = "/customer")
public class CustomerController {

	@Autowired
	CustomerService customerService;

	@GetMapping
	public Page<Customer> showCustomers(Pageable pageable) {
		return customerService.showCustomers(pageable);
	}

	@GetMapping("/{id}")
	@PreAuthorize("hasRole('ROLE_PRODUCT_ADMIN')")
	public Customer getProduct(@PathVariable("id") Long id) {
		return customerService.findCustomerById(id).orElse(null);
	}

}