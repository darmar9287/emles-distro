package com.emles;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point class for app.
 * 
 * @author Dariusz Kulig
 *
 */
@SpringBootApplication
public class EmlesOauthServerApplication {

	/**
	 * Entry point of application.
	 * 
	 * @param args - command line arguments
	 */
	public static void main(String[] args) {
		SpringApplication.run(EmlesOauthServerApplication.class, args);
	}
}
