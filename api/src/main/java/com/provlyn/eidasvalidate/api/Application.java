package com.provlyn.eidasvalidate.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Service entry point.
 *
 * <p>Public and unauthenticated by design: the argument this service exists to
 * make is that verification should not require trusting Provlyn, and gating it
 * would undercut that. Rate limiting rather than authentication.
 *
 * <p>Nothing submitted is retained. No request body is logged.
 */
@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
