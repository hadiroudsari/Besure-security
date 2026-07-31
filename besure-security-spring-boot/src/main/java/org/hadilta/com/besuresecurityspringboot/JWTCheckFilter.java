package org.hadilta.com.besuresecurityspringboot;

import decoder.JWTTokenDecoder;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class JWTCheckFilter implements Filter {

private final AuthorizationManager authorizationManager;

    public JWTCheckFilter(AuthorizationManager authorizationManager) {
        this.authorizationManager = authorizationManager;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest hsr = (HttpServletRequest) servletRequest;
        String authorizationHeader = hsr.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            authorizationHeader = authorizationHeader.substring(7);
        }

        assert authorizationHeader != null;
        var decoded= JWTTokenDecoder.oneInstance().decode(authorizationHeader);
        HttpServletRequest request =
                (HttpServletRequest) servletRequest;
       boolean hasAccess = authorizationManager.hasAccess(decoded.roles(),request.getRequestURI());

        if (!hasAccess) {
            HttpServletResponse response =
                    (HttpServletResponse) servletResponse;
            response.sendError(
                    HttpServletResponse.SC_FORBIDDEN,
                    "Access denied"
            );
            return;
        }

        filterChain.doFilter(servletRequest, servletResponse);

    }
}
