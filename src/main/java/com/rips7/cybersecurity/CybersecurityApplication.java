package com.rips7.cybersecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication(exclude = SecurityAutoConfiguration.class)
@ComponentScan({"com.rips7.cybersecurity"})
public class CybersecurityApplication {

  public static void main(String[] args) {
    SpringApplication.run(CybersecurityApplication.class, args);
  }
}
