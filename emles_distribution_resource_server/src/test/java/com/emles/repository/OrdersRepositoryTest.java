package com.emles.repository;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

import javax.transaction.Transactional;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.PropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.emles.model.Product;

@RunWith(SpringRunner.class)
@Transactional
@SpringBootTest
@PropertySource("application-test.properties")
public class OrdersRepositoryTest {
	@Autowired
    private OrderRepository orderRepository;

	private Product expectedProduct;
	
	@Before
	public void setupProduct() {
		expectedProduct = new Product("SOS 1", 10L, new BigDecimal(9.99));
		expectedProduct.setId(2L);
	}
	
//    @Test
//    public void testFindAllShouldReturnTwoProducts() {
//        List<Product> products = productRepository.findAll();
//        int productsSize = 2;
//        assertNotNull("Product list is null.", products);
//        assertTrue(products.size() == productsSize);
//    }
    
//    @Test
//    public void testFindByIdShouldReturnSecondProduct() {
//    	Long secondProductId = 2L;    	
//    	Optional<Product> product = productRepository.findById(secondProductId);  
//    	assertTrue("Product name is different than expected product name", product.get().getName().equals(expectedProduct.getName()));    	
//    }
    
//    @Test
//    public void testSaveProductShouldReturnSavedProduct() {    	
//		productRepository.save(expectedProduct);
//		Long searchedProductId = 2L;
//		Product found = productRepository.getOne(searchedProductId);
//		assertTrue(found.getName().equals(expectedProduct.getName()));
//    }
	
}