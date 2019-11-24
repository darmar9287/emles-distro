package com.emles.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;

import com.emles.model.Product;
import com.emles.service.ProductService;
import com.emles.utils.Utils;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.validation.Valid;

@RestController
@RequestMapping(value = "/product")
public class ProductController {

	@Autowired
	private ProductService productService;

	@GetMapping
	public List<Product> products() {
		return productService.showProducts();
	}

	@GetMapping("/{id}")
	@PreAuthorize("hasRole('ROLE_PRODUCT_ADMIN')")
	public ResponseEntity<?> getProduct(@PathVariable("id") Long id) {
		Optional<Product> productOpt = productService.findProductById(id);
		if (productOpt.isPresent()) {
			return ResponseEntity.ok(productOpt.get());
		}
		return ResponseEntity.notFound().build();
	}

	@GetMapping("/products")
	@PreAuthorize("hasRole('ROLE_PRODUCT_ADMIN')")
	public List<Product> findAll() {
		return productService.showProducts();
	}
	
	@PostMapping("/")
	@PreAuthorize("hasAuthority('ROLE_PRODUCT_ADMIN')")
	public ResponseEntity<?> createProduct(@RequestBody @Valid  Product product, Errors errors) {
		if (errors.hasErrors()) {
			List<Map<String, String>> errorMessages = Utils.extractErrorMessagesFromField(errors);
			return ResponseEntity.unprocessableEntity().body(errorMessages);
		}
		productService.addProduct(product);
		return ResponseEntity.ok().build();
	}
	
	@PutMapping("/update")
	@PreAuthorize("hasAuthority('ROLE_PRODUCT_ADMIN')")
	public ResponseEntity<?> updateProduct(@Valid @RequestBody Product product, Errors errors) {
		if (!productService.findProductById(product.getProductId()).isPresent()) {
			return ResponseEntity.notFound().build();
		}
		if (errors.hasErrors()) {
			List<Map<String, String>> errorMessages = Utils.extractErrorMessagesFromField(errors);
			return ResponseEntity.unprocessableEntity().body(errorMessages);
		}
		productService.updateProduct(product);
		return ResponseEntity.ok().build();
	}
}