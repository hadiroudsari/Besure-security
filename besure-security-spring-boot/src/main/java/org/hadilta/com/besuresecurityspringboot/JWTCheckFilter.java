package org.hadilta.com.besuresecurityspringboot;

import decoder.JWTTokenDecoder;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class JWTCheckFilter implements Filter {


//    private final ServletRequest httpServletRequest;

    public JWTCheckFilter(/*ServletRequest httpServletRequest*/) {
        System.out.println("JWTCheckFilter CREATED");
//        this.httpServletRequest = httpServletRequest;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("JWTCheckFilter EXECUTED");
        HttpServletRequest hsr = (HttpServletRequest) servletRequest;
        String authorizationHeader = hsr.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            authorizationHeader =authorizationHeader.substring(7);
        }

        var decoded= JWTTokenDecoder.oneInstance().decode(authorizationHeader);

        filterChain.doFilter(servletRequest, servletResponse);

    }
}
