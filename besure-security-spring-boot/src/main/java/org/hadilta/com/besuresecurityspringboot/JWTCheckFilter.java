package org.hadilta.com.besuresecurityspringboot;

import decoder.JWTTokenDecoder;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class JWTCheckFilter implements Filter {

    public JWTCheckFilter() {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest hsr = (HttpServletRequest) servletRequest;
        String authorizationHeader = hsr.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            authorizationHeader = authorizationHeader.substring(7);
        }

        var decoded= JWTTokenDecoder.oneInstance().decode(authorizationHeader);

        filterChain.doFilter(servletRequest, servletResponse);

    }
}
