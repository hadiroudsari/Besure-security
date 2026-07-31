package org.hadilta.com.besuresecurityspringboot;


import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class AuthorizationManager {

    public boolean isDefaultPermission = false;

    Map<String, Set<String>> resourceToRole=new HashMap<>();

   public void addRoleToResource(String resource, String role){
       if(resourceToRole.containsKey(resource)){
           resourceToRole.get(resource).add(role);
       }
       else{
           resourceToRole.put(resource,new HashSet<>(Set.of(role)));
       }
    }

   public boolean hasAccess(Set<String> userRoles, String resource){
      var acceptableRoles= resourceToRole.get(resource);

      if(acceptableRoles == null && !isDefaultPermission) {
          return false;
      } else if (acceptableRoles == null) {
          return true;
      }

      return acceptableRoles.stream()
              .anyMatch(userRoles::contains);
   }

}



