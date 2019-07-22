package com.emles.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import com.emles.model.Product;
import com.emles.service.ProductService;

import java.util.List;


@RestController
@RequestMapping(value = "/product")
public class ProductController {

	@Autowired
    ProductService productService;

    @GetMapping
    public List<Product> products() {
        return productService.showProducts();
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ROLE_PRODUCT_ADMIN')")
    public Product getProduct(@PathVariable("id") Long id) {
        return productService.findProductById(id)
                                 .orElse(null);
    }

    @GetMapping("/search/")
    @PreAuthorize("hasRole('ROLE_PRODUCT_ADMIN')")
    public Product findByName(@RequestParam("name") String name) {
        return productService.findProductByName(name);
    }
    
    @GetMapping("/products")
    @PreAuthorize("hasRole('ROLE_PRODUCT_ADMIN')")
    public List<Product> findAll() {
        return productService.showProducts();
    }
}