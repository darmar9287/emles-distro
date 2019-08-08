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

	@Override
	public Optional<Product> findProductById(long productId) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Product findProductByName(String name) {
		// TODO Auto-generated method stub
		return null;
	}
}
