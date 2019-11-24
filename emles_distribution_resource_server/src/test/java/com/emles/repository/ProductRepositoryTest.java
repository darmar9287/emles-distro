package com.emles.repository;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;


import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.EmbeddedDatabaseConnection;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.emles.model.Product;

@RunWith(SpringRunner.class)
@DataJpaTest
@AutoConfigureTestDatabase(connection = EmbeddedDatabaseConnection.H2)
@TestPropertySource("classpath:application-repository-test.properties")
public class ProductRepositoryTest {
	@Autowired
    private ProductRepository productRepository;

	private Product expectedProduct;
	
	@Before
	public void setupProduct() {
		expectedProduct = new Product("SOS 11", 10L, new BigDecimal(9.99));
		expectedProduct.setProductId(3L);
		
		Product product = new Product();
	    product.setProductName("SOS 12");
	    product.setProductPrice(new BigDecimal("9.99"));
	    product.setProductQuantityLeft(10L);
	    
	    productRepository.save(product);
	    
	    product = new Product();
	    product.setProductName("SOS 11");
	    product.setProductPrice(new BigDecimal("9.99"));
	    product.setProductQuantityLeft(20L);
	    
	    productRepository.save(product);
	}
	
    @Test
    public void testFindAllShouldReturnTwoProducts() {
        List<Product> products = productRepository.findAll();
        int productsSize = 2;
        assertNotNull("Product list is null.", products);
        assertTrue(products.size() == productsSize);
    }
    
    @Test
    public void testSaveProductShouldReturnSavedProduct() {    	
		productRepository.save(expectedProduct);
		Long searchedProductId = 3L;
		Product found = productRepository.getOne(searchedProductId);
		assertTrue(found.getProductName().equals(expectedProduct.getProductName()));
    }
	
}