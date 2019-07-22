package com.emles.service;

import java.util.List;

import com.emles.model.Product;

public interface ProductService {
	
	public void addProduct(Product product);
	
	public void deleteProduct(Product product);
	
	public void updateProduct(Product producy);
	
	public List<Product> showProducts();

}
