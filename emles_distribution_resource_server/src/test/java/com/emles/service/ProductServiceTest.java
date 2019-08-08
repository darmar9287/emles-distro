package com.emles.service;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Mockito.*;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;

import com.emles.model.Product;
import com.emles.repository.ProductRepository;

@RunWith(SpringRunner.class)
public class ProductServiceTest {
	
	@InjectMocks
    private ProductService productService = new ProductServiceImpl();
	
	@Mock
	private ProductRepository productRepository;
	
	List<Product> products = new ArrayList<>();
	
	@Before
	public void setupProducts() {
		Product firstProduct = new Product("SOS", 10L, new BigDecimal(9.99));
		firstProduct.setId(1L);
		Product secondProduct = new Product("SOS 1", 10L, new BigDecimal(9.99));
		secondProduct.setId(2L);
		products.add(firstProduct);
		products.add(secondProduct);		
	}
	
	@Test
	public void testFindById() {
		Product product = products.get(0);
		when(productRepository.findById(1L)).thenReturn(Optional.of(product));
		Optional<Product> found = productService.findProductById(1L);
		Mockito.verify(productRepository).findById(1L);
		assertTrue(product.getName().equals(found.get().getName()));
	}

}
