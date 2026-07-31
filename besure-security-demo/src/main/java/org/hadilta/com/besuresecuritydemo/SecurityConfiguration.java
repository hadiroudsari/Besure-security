package org.hadilta.com.besuresecuritydemo;

import org.hadilta.com.besuresecurityspringboot.AuthorizationManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SecurityConfiguration {

    @Bean
    public AuthorizationManager authorizationManager() {

        AuthorizationManager manager = new AuthorizationManager();

//        manager.isDefaultPermission = true;
        manager.addRoleToResource("/admin", "user_premium");
        manager.addRoleToResource("/profile", "user");
        manager.addRoleToResource("/profile", "user_premium");
//        manager.addRoleToResource("/hello", "user_premium");


        return manager;
    }
}

