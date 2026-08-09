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
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            authHeader = authHeader.substring(7);
        }
        // todo: handle cases when Authorization isn't Bearer or it's absent - at least throw a friendly error
        assert authHeader != null;
        var decoded = JWTTokenDecoder.oneInstance().decode(authHeader);
        // todo: handle the case when JWT doesn't have roles field or it's a null
        if (!authorizationManager.hasAccess(decoded.roles(), request.getRequestURI())) {
            HttpServletResponse response = (HttpServletResponse) servletResponse;
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
            return;
        }

        filterChain.doFilter(servletRequest, servletResponse);

    }
}
