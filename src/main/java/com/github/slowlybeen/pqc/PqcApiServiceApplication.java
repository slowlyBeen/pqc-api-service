package com.github.slowlybeen.pqc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
public class PqcApiServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(PqcApiServiceApplication.class, args);
    }

}
