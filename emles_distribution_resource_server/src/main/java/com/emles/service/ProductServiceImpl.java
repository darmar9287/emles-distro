package com.emles.service;

import java.util.List;
import java.util.Optional;
import javax.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.emles.model.Product;
import com.emles.repository.ProductRepository;

@Service
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
		productRepository.delete(product);

	}

	@Override
	public List<Product> showProducts() {		
		return productRepository.findAll();
	}

	@Override
	public Optional<Product> findProductById(long productId) {
		return productRepository.findById(productId);
	}
}
