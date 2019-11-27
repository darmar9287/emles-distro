package com.emles.integration;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.emles.EmlesDistributionResourceServerApplication;
import com.emles.model.Product;
import com.emles.repository.ProductRepository;
import com.emles.utils.Utils;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;

@RunWith(SpringRunner.class)
@SpringBootTest(
	webEnvironment = WebEnvironment.DEFINED_PORT,
	classes = EmlesDistributionResourceServerApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties")
@DirtiesContext(classMode = ClassMode.AFTER_EACH_TEST_METHOD)
public class ProductIntegrationTest {
	
	private String username = "product_admin";
	
	private String password = "user";
	
	@Autowired
	private ProductRepository productRepository;
	
	@LocalServerPort
	int port;
	
	@Before
	public void init() {
	    RestAssured.port = port;
	    productRepository.deleteAll();
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
	public void testFetchProducts() throws Exception {
	    
	    String accessToken = signIn(username, password);
	    
	    Response response = RestAssured
	    	.given()
	    	.contentType(ContentType.JSON)
	    	.header("Authorization", "Bearer " + accessToken)
	    	.log()
	    	.all()
	    	.when()
	    	.get("/product/products")
	    	.thenReturn();

	    List<Object> responseList = response.jsonPath().getList("");
	    assertTrue(responseList.size() == 2);
	}
	
	@Test
	public void testCreateProductSuccess() throws Exception {		
	    String accessToken = signIn(username, password);
	    Product product = new Product();
	    product.setProductName("SOS 11");
	    product.setProductPrice(new BigDecimal("22.11"));
	    product.setProductQuantityLeft(10L);
	    
	    Response response = sendCreateProductRequest(product, accessToken);
	    
	    assertEquals(200, response.getStatusCode());
	    signOut(accessToken , 204);
	}
	
	@Test
	public void testCreateProductFailsWhenProductParamsAreInvalid() throws Exception {

	    String accessToken = signIn(username, password);
	    
	    Product product = new Product();
	    product.setProductName(" SOS 11");
	    product.setProductPrice(new BigDecimal("22.11"));
	    product.setProductQuantityLeft(-1L);
	    
	    Response response = sendCreateProductRequest(product, accessToken);
	    
	    assertEquals(422, response.getStatusCode());
	    List<Object> errorMessages = response.body().jsonPath().getList("");
	    verifyProductErrorMessages(errorMessages);
	    signOut(accessToken , 204);
	}
	
	@Test
	public void testUpdateProductFailsWhenProductIdIsInvalid() throws Exception {

	    String accessToken = signIn(username, password);
	    Product product = productRepository.findByProductName("SOS 12");
	    product.setProductId(-19L);
	    product.setProductName("SOS 12");
	    product.setProductPrice(new BigDecimal("22.22"));
	    product.setProductQuantityLeft(199L);
	    
	    Response response = sendUpdateProductRequest(product, accessToken);
	    
	    assertEquals(404, response.getStatusCode());
	    signOut(accessToken , 204);
	}
	
	@Test
	public void testUpdateProductFailsWhenProductDataIsInvalid() throws Exception {

	    String accessToken = signIn(username, password);
	    Product product = productRepository.findByProductName("SOS 12");
	    product.setProductName(" SOS 12" );
	    product.setProductPrice(new BigDecimal("22.22"));
	    product.setProductQuantityLeft(-199L);
	    
	    Response response = sendUpdateProductRequest(product, accessToken);
	    
	    assertEquals(422, response.getStatusCode());
	    List<Object> errorMessages = response.body().jsonPath().getList("");
	    verifyProductErrorMessages(errorMessages);
	    signOut(accessToken , 204);
	}
	
	@Test
	public void testUpdateProductSuccess() throws Exception {

	    String accessToken = signIn(username, password);
	    Product product = productRepository.findByProductName("SOS 12");
	    product.setProductName("SOS 13");
	    product.setProductPrice(new BigDecimal("22.22"));
	    product.setProductQuantityLeft(200L);
	    
	    Response response = sendUpdateProductRequest(product, accessToken);
	    
	    assertEquals(200, response.getStatusCode());
	    product = productRepository.findByProductName("SOS 13");
	    assertTrue(product.getProductPrice().equals(new BigDecimal("22.22")));
	    assertEquals(200L, product.getProductQuantityLeft().longValue());
	    signOut(accessToken , 204);
	}

	private void verifyProductErrorMessages(List<Object> errorMessages) {
		@SuppressWarnings("unchecked")
		List<String> errorStrings = errorMessages.stream().map(errorMessage -> {
			return new ArrayList<String>(((Map<String, String>)errorMessage).values());
	    }).flatMap(List::stream).collect(Collectors.toList());
	    
	    assertTrue(errorStrings.contains(Utils.invalidProductNameMsg));
	    assertTrue(errorStrings.contains(Utils.invalidProductQuantityMsg));
	}
	
	private Response sendUpdateProductRequest(Product product, String accessToken) throws Exception {
		return RestAssured
    	.given()
    	.contentType(ContentType.JSON)
    	.header("Authorization", "Bearer " + accessToken)
    	.log()
    	.all()
    	.when()
    	.body(product)
    	.put("/product/update")
    	.thenReturn();
	}
	
	private Response sendCreateProductRequest(Product product, String accessToken) throws Exception {
		return RestAssured
    	.given()
    	.contentType(ContentType.JSON)
    	.header("Authorization", "Bearer " + accessToken)
    	.log()
    	.all()
    	.when()
    	.body(product)
    	.post("/product/")
    	.thenReturn();
	}
	
	private String signIn(String username, String password) throws Exception {
		Response response = RestAssured
			    .given()
			    .header("Authorization", "Basic Y3VybF9jbGllbnQ6dXNlcg==")
			    .param("grant_type", "password")
			    .param("username", username)
			    .param("password", password)
			    .param("client_id", "curl_client")
			    .log()
			    .all()
			    .when()
			    .post("http://authservertest:8084/oauth/token")
			    .thenReturn();
		return (String)response.body().jsonPath().get("access_token");
	}
	
	private void signOut(String accessToken, int expectedStatus) throws Exception {
		Response response = RestAssured
		    	.given()
		    	.contentType(ContentType.JSON)
		    	.param("grant_type", password)
		    	.param("client_id", "integration_test_product_admin")
		    	.header("Authorization", "Bearer " + accessToken)
		    	.log()
		    	.all()
		    	.when()
		    	.delete("http://authservertest:8084/sign_out")
		    	.thenReturn();
		assertEquals(expectedStatus, response.getStatusCode());
	}
}
