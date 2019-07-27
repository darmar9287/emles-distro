package com.emles.integration;


import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import com.emles.EmlesDistributionResourceServerApplication;


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
	
	@LocalServerPort
	int port;
	
	@Before
	public void init() {
	    RestAssured.port = port;
	}

	@Test
	public void testFetchProducts() throws Exception {

	    Response response = RestAssured
		    .given()
		    .header("Authorization", "Basic Y3VybF9jbGllbnQ6dXNlcg==")
		    .param("grant_type", "password")
		    .param("username", "product_admin")
		    .param("password", "user")
		    .param("client_id", "curl_client")
		    .log()
		    .all()
		    .when()
		    .post("http://authserver:8081/oauth/token")
		    .thenReturn();
	    
	    String accessToken = (String)response.body().jsonPath().get("access_token");
	    
	    response = RestAssured
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
}
