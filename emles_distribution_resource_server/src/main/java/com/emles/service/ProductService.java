package com.emles.service;

import java.util.List;
import java.util.Optional;
import com.emles.model.Product;

public interface ProductService {
	
	public void addProduct(Product product);
	
	public void deleteProduct(Product product);
	
	public void updateProduct(Product product);
		
	public Optional<Product> findProductById(long productId);
	
	public List<Product> showProducts();
	
	public Product findProductByName(String name);
}
