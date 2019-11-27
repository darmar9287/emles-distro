package com.emles.controller;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.emles.model.Customer;
import com.emles.service.CustomerService;

@RestController
@RequestMapping(value = "/customer")
public class CustomerController {

	private static final int PER_PAGE = 5;
	
	@Autowired
	private CustomerService customerService;

	@DeleteMapping("/{id}")
	@PreAuthorize("hasAuthority('ROLE_PRODUCT_ADMIN')")
	public ResponseEntity<?> deleteCustomer(@PathVariable("id") Long id) {
		Optional<Customer> customerOpt = customerService.findCustomerById(id);
		if (customerOpt.isPresent()) {
			customerService.deleteCustomer(id);
			return ResponseEntity.noContent().build();
		}
		return ResponseEntity.notFound().build();
	}
	
	@GetMapping("/{id}")
	@PreAuthorize("hasAuthority('ROLE_PRODUCT_ADMIN')")
	public ResponseEntity<?> getCustomer(@PathVariable("id") Long id) {
		Optional<Customer> customerOpt = customerService.findCustomerById(id);
		if (customerOpt.isPresent()) {
			return ResponseEntity.ok(customerOpt.get());
		}
		return ResponseEntity.notFound().build();
	}

	@GetMapping(value = {"/list/{page}", "/list"})
	@PreAuthorize("hasAuthority('ROLE_PRODUCT_ADMIN')")
	public Page<Customer> findAll(@PathVariable(name = "page", required = false) Integer page,
			@RequestParam(name = "searchTerm", defaultValue = "", required = false) String searchTerm) {
		if (page == null) {
			page = 0;
		}
		Pageable pageable = PageRequest.of(page, PER_PAGE);
		return customerService.findCustomersByName(searchTerm, pageable);
	}
	
	@PostMapping("/")
	@PreAuthorize("hasAuthority('ROLE_PRODUCT_ADMIN')")
	public ResponseEntity<?> createCustomer(@RequestBody @Valid  Customer customer, Errors errors) {
		return saveCustomer(customer, errors);
	}
	
	@PutMapping("/update")
	@PreAuthorize("hasAuthority('ROLE_PRODUCT_ADMIN')")
	public ResponseEntity<?> updateCustomer(@Valid @RequestBody Customer customer, Errors errors) {
		if (!customerService.findCustomerById(customer.getCustomerId()).isPresent()) {
			return ResponseEntity.notFound().build();
		}
		return saveCustomer(customer, errors);
	}

	private ResponseEntity<?> saveCustomer(Customer customer, Errors errors) {
		List<String> errorMessages = new ArrayList<>();
		Customer created = customerService.saveCustomer(customer, errors, errorMessages);
		
		if (errorMessages.isEmpty()) {
			return ResponseEntity.ok(created);
		}
		Map<String, List<String>> responseMap = new HashMap<>();
		responseMap.put("errors", errorMessages);
		return ResponseEntity.unprocessableEntity().body(responseMap);
	}
}
