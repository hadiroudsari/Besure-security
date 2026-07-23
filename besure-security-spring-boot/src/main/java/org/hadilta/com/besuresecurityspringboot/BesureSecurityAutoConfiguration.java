package org.hadilta.com.besuresecurityspringboot;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class BesureSecurityAutoConfiguration {

    @Bean
    public JWTCheckFilter jwtCheckFilter() {
        return new JWTCheckFilter();
    }
}