package com.emles.service;

import java.util.List;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;

import com.emles.model.Product;
import com.emles.repository.ProductRepository;

public class ProductServiceImpl implements ProductService {	
	
	@Autowired
	ProductRepository productRepository;
	
	@Override
	@Transactional
	public void addProduct(Product product) {
		productRepository.save(product);

	}

	@Override
	public void deleteProduct(Product product) {
		// TODO Auto-generated method stub

	}

	@Override
	public void updateProduct(Product producy) {
		// TODO Auto-generated method stub

	}

	@Override
	public List<Product> showProducts() {
		// TODO Auto-generated method stub
		return null;
	}

}
