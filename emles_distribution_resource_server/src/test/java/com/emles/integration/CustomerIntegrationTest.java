package com.emles.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.emles.EmlesDistributionResourceServerApplication;
import com.emles.model.Customer;
import com.emles.repository.CustomerRepository;
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
public class CustomerIntegrationTest {

	@LocalServerPort
	int port;
	
	@Autowired
	private CustomerRepository customerRepository;
	
	private String[] names = {
		"Marie Scott",
		"Russell Sanchez",
		"Daniel Smith",
		"Kathy Carter",
		"Frances Perez",
		"Kathleen Morris",
		"Katherine Russell",
		"Jason Powell",
		"Stephanie Phillips",
		"James Reed"	
	};
	
	private String username = "product_admin";
	
	private String password = "user";
	
	@Before
	public void setUp() {
		RestAssured.port = port;
		customerRepository.deleteAll();
		IntStream.rangeClosed(1, 10).forEach(i -> {
			Customer c = new Customer();
			c.setCustomerAddress(String.format("customer%d@test.com", i));
			c.setCustomerName(names[i - 1]);
			c.setCustomerPhone(String.format("7008009%d", i + 10));
			customerRepository.save(c);
		});
	}
	
	@Test
	public void testCreateCustomerSuccess() throws Exception {		
	    String accessToken = signIn(username, password);
	    Customer customer = new Customer();
	    customer.setCustomerAddress("customer_emles@test.com");
	    customer.setCustomerName("Marek Polny");
	    customer.setCustomerPhone("997997997");
	    Response response = sendCreateCustomerRequest(customer, accessToken);
	    
	    assertEquals(200, response.getStatusCode());

	    signOut(accessToken , 204);
	    
	    Customer found = customerRepository.findByCustomerAddress(customer.getCustomerAddress());
	    assertNotNull(found);
	    assertTrue(found.getCustomerName().equals(customer.getCustomerName()));
	    assertTrue(found.getCustomerPhone().equals(customer.getCustomerPhone()));
	}
	
	@Test
	public void testCreateCustomerShouldReturn422WhenDataIsInvalid() throws Exception {		
	    String accessToken = signIn(username, password);
	    Customer customer = new Customer();
	    customer.setCustomerAddress("customer_emlescom");
	    customer.setCustomerName(" Marek Polny1 ");
	    customer.setCustomerPhone("99799799712");
	    Response response = sendCreateCustomerRequest(customer, accessToken);
	    
	    assertEquals(422, response.getStatusCode());
	    
	    @SuppressWarnings("unchecked")
		List<String> errorMessages = (List<String>)response.getBody().jsonPath().get("errors");
	    assertEquals(errorMessages.size(), 3);
	    assertTrue(errorMessages.contains(Utils.invalidCustomerNameRegex));
	    assertTrue(errorMessages.contains(Utils.invalidEmailAddressMsg));
	    assertTrue(errorMessages.contains(Utils.invalidPhoneNumberMsg));
	    
	    signOut(accessToken , 204);
	}
	
	@Test
	public void testCreateCustomerShouldReturn422WhenEmailAndPhoneExist() throws Exception {		
	    String accessToken = signIn(username, password);
	    Customer customer = new Customer();
	    customer.setCustomerAddress("customer1@test.com");
	    customer.setCustomerName("Marek Polny");
	    customer.setCustomerPhone("700800911");
	    Response response = sendCreateCustomerRequest(customer, accessToken);
	    
	    assertEquals(422, response.getStatusCode());
	    
	    @SuppressWarnings("unchecked")
		List<String> errorMessages = (List<String>)response.getBody().jsonPath().get("errors");
	    assertEquals(errorMessages.size(), 2);
	    assertTrue(errorMessages.contains(Utils.emailExistsMsg));
	    assertTrue(errorMessages.contains(Utils.phoneNumberExistsMsg));
	    
	    signOut(accessToken , 204);
	}
	
	@Test
	public void testUpdateCustomerSuccess() throws Exception {		
	    String accessToken = signIn(username, password);
	    Customer customer = customerRepository.findByCustomerAddress("customer1@test.com");
	    customer.setCustomerAddress("customer_emles1@testing.com");
	    customer.setCustomerName("Marek Jeziorny");
	    customer.setCustomerPhone("997998999");
	    
	    Response response = sendUpdateCustomerRequest(customer, accessToken);
	    
	    assertEquals(200, response.getStatusCode());
	    signOut(accessToken , 204);
	    
	    Customer found = customerRepository.findByCustomerAddress(customer.getCustomerAddress());
	    assertNotNull(found);
	    assertTrue(found.getCustomerName().equals(customer.getCustomerName()));
	    assertTrue(found.getCustomerPhone().equals(customer.getCustomerPhone()));
	    
	    found = customerRepository.findByCustomerAddress("customer1@test.com");
	    assertNull(found);
	}
	
	@Test
	public void testUpdateCustomerReturns404WhenUserIdIsInvalid() throws Exception {		
	    String accessToken = signIn(username, password);
	    Customer customer = customerRepository.findByCustomerAddress("customer1@test.com");
	    customer.setCustomerAddress("customer_emles1@testing.com");
	    customer.setCustomerName("Marek Jeziorny");
	    customer.setCustomerPhone("997998999");
	    customer.setCustomerId(Long.MAX_VALUE);
	    
	    Response response = sendUpdateCustomerRequest(customer, accessToken);
	    
	    assertEquals(404, response.getStatusCode());
	    signOut(accessToken , 204);
	}
	
	@Test
	@SuppressWarnings("unchecked")
	public void testPaginationOfCustomers() throws Exception {		
	    String accessToken = signIn(username, password);
	    String searchTerm = "Kath";
	    final int PER_PAGE = 5;
	    Response response = null;
	    
	    for (int i = 0; i < 3; i++) {
	    	response = sendFetchCustomersRequest(i, "", accessToken);
	    	Pageable pageable = PageRequest.of(i, PER_PAGE);
			List<Object> customersJsonArray = (List<Object>)response.getBody().jsonPath().get("content");
	    	List<Customer> customersList = customerRepository.findAll(pageable).getContent();
	    	
	    	for (int j = 0; j < customersJsonArray.size(); j++) {
	    		Map<String, String> customerMap = (Map<String, String>)customersJsonArray.get(j);
	    		Customer customer = customersList.get(j);
	    		assertEquals(customerMap.get("customerAddress"), customer.getCustomerAddress());
	    		assertEquals(customerMap.get("customerPhone"), customer.getCustomerPhone());
	    		assertEquals(customerMap.get("customerName"), customer.getCustomerName());
	    	}
	    	assertEquals(200, response.getStatusCode());
	    }
	    
	    response = sendFetchCustomersRequest(0, searchTerm, accessToken);
	    Pageable pageable = PageRequest.of(0, PER_PAGE);
	    List<Object> customersJsonArray = (List<Object>)response.getBody().jsonPath().get("content");
	    List<Customer> customersList = customerRepository.findByName(searchTerm, pageable).getContent();
	    assertEquals(customersJsonArray.size(), 3);
	    for (int j = 0; j < customersJsonArray.size(); j++) {
    		Map<String, String> customerMap = (Map<String, String>)customersJsonArray.get(j);
    		Customer customer = customersList.get(j);
    		assertEquals(customerMap.get("customerAddress"), customer.getCustomerAddress());
    		assertEquals(customerMap.get("customerPhone"), customer.getCustomerPhone());
    		assertEquals(customerMap.get("customerName"), customer.getCustomerName());
    	}
	    signOut(accessToken , 204);
	}
	
	@SuppressWarnings("unchecked")
	@Test
	public void testFetchCustomer() throws Exception {		
	    String accessToken = signIn(username, password);
	    Customer customer = customerRepository.findByCustomerAddress("customer1@test.com");
	    long customerId = customer.getCustomerId();
	    
	    Response response = sendFetchCustomerRequest(customerId, accessToken);
	    Map<String, String> customerMap = (Map<String, String>)response.getBody().jsonPath().get("");
	    
	    assertEquals(customerMap.get("customerAddress"), customer.getCustomerAddress());
		assertEquals(customerMap.get("customerPhone"), customer.getCustomerPhone());
		assertEquals(customerMap.get("customerName"), customer.getCustomerName());
	    
	    assertEquals(200, response.getStatusCode());
	    
	    response = sendFetchCustomerRequest(Long.MAX_VALUE, accessToken);
	    assertEquals(404, response.getStatusCode());
	    
	    signOut(accessToken , 204);
	}
	
	@Test
	public void testDeleteCustomer() throws Exception {		
	    String accessToken = signIn(username, password);
	    Customer customer = customerRepository.findByCustomerAddress("customer1@test.com");
	    long customerId = customer.getCustomerId();
	    
	    Response response = sendDeleteCustomerRequest(customerId, accessToken);
	    
	    assertEquals(204, response.getStatusCode());
	    
	    customer = customerRepository.findByCustomerAddress("customer1@test.com");
	    assertNull(customer);
	    
	    response = sendFetchCustomerRequest(Long.MAX_VALUE, accessToken);
	    assertEquals(404, response.getStatusCode());
	    
	    signOut(accessToken , 204);
	}
	
	private Response sendDeleteCustomerRequest(long customerId, String accessToken) {
		return RestAssured
		    	.given()
		    	.contentType(ContentType.JSON)
		    	.header("Authorization", "Bearer " + accessToken)
		    	.log()
		    	.all()
		    	.when()
		    	.delete("/customer/" + customerId)
		    	.thenReturn();
	}

	private Response sendFetchCustomerRequest(long customerId, String accessToken) {
		return RestAssured
		    	.given()
		    	.contentType(ContentType.JSON)
		    	.header("Authorization", "Bearer " + accessToken)
		    	.log()
		    	.all()
		    	.when()
		    	.get("/customer/" + customerId)
		    	.thenReturn();
	}

	private Response sendFetchCustomersRequest(int page, String searchTerm, String accessToken) {
		return RestAssured
		    	.given()
		    	.contentType(ContentType.JSON)
		    	.header("Authorization", "Bearer " + accessToken)
		    	.log()
		    	.all()
		    	.when()
		    	.get("/customer/list/" + page + (!searchTerm.isEmpty() ? "?searchTerm=" + searchTerm : ""))
		    	.thenReturn();
	}

	private Response sendUpdateCustomerRequest(Customer customer, String accessToken) {
		return RestAssured
		    	.given()
		    	.contentType(ContentType.JSON)
		    	.header("Authorization", "Bearer " + accessToken)
		    	.log()
		    	.all()
		    	.when()
		    	.body(customer)
		    	.put("/customer/update")
		    	.thenReturn();
	}

	private Response sendCreateCustomerRequest(Customer customer, String accessToken) {
		return RestAssured
		    	.given()
		    	.contentType(ContentType.JSON)
		    	.header("Authorization", "Bearer " + accessToken)
		    	.log()
		    	.all()
		    	.when()
		    	.body(customer)
		    	.post("/customer/")
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
