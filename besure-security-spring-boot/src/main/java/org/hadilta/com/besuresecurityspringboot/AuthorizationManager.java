package org.hadilta.com.besuresecurityspringboot;


import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class AuthorizationManager {

    public boolean isAccessibleByDefault;

    Map<String, Set<String>> resourceToRole=new HashMap<>();

    public AuthorizationManager() {
        isAccessibleByDefault = false;
    }
    public AuthorizationManager(boolean isAccessibleByDefault) {
        this.isAccessibleByDefault = isAccessibleByDefault;
    }

    public void addRoleToResource(String resource, String role){
       resourceToRole.computeIfAbsent(resource, k -> new HashSet<>()).add(role);
    }

    public boolean hasAccess(Set<String> userRoles, String resource) {
        var acceptableRoles = resourceToRole.get(resource);
        if (acceptableRoles == null)
            return isAccessibleByDefault;
        return acceptableRoles.stream()
                .anyMatch(userRoles::contains);
    }

}



