package com.emles.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.emles.model.AppUser;
import com.emles.model.Customer;
import com.emles.model.Product;
import com.emles.service.OrderService;

@RestController
@RequestMapping(value = "/orders")
public class OrderController {

	@Autowired
	OrderService orderService;

	@PostMapping("/processOrder")
	@PreAuthorize("hasRole('ROLE_PRODUCT_ADMIN')")
	public void processOrder(@RequestBody Map<String, Object> payload) {
		
		//orderService.addOrder(user, customer, products);
	}
}