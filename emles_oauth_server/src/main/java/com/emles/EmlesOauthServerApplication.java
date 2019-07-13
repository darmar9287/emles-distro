package com.emles;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point class for app.
 * @author Dariusz Kulig
 *
 */
@SpringBootApplication
public final class EmlesOauthServerApplication {

    /**
     * Constructor needed by codestyle.
     */
    private EmlesOauthServerApplication() {
    }
    /**
     * Entry point of application.
     * @param args - command line arguments
     */
     public static void main(final String[] args) {
          SpringApplication.run(EmlesOauthServerApplication.class, args);
     }
}
