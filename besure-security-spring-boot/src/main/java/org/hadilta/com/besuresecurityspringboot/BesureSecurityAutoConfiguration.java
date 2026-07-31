package org.hadilta.com.besuresecurityspringboot;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class BesureSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(AuthorizationManager.class)
    public AuthorizationManager authorizationManager() {
        return new AuthorizationManager();
    }

    @Bean
    public JWTCheckFilter jwtCheckFilter(AuthorizationManager authorizationManager)
    {
        return new JWTCheckFilter(authorizationManager);
    }
}