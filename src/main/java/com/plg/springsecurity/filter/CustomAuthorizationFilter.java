package com.plg.springsecurity.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    if (request.getServletPath().equals("/api/login") || request.getServletPath().equals("token/refresh/**")) {
      filterChain.doFilter(request, response);
    } else {
      String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
      if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
        try {
          String token = authorizationHeader.substring("Bearer ".length());
          Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
          JWTVerifier verifier = JWT.require(algorithm).build();
          DecodedJWT decodedJWT = verifier.verify(token);
          String username = decodedJWT.getSubject();

          Map<String, Claim> claims = decodedJWT.getClaims();
          Claim claim = claims.get("roles");
          String[] roles = claim.asArray(String.class);
          Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
          Arrays.stream(roles).forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role));
          });
          UsernamePasswordAuthenticationToken autehenticationToken = new UsernamePasswordAuthenticationToken(username,
              null, authorities);
          SecurityContextHolder.getContext().setAuthentication(autehenticationToken);
          filterChain.doFilter(request, response);
        } catch (Exception e) {
          log.info("Error login in : {}", e.getMessage());
          response.setHeader("Error", e.getMessage());
          response.setStatus(HttpStatus.FORBIDDEN.value());
          // response.sendError(HttpStatus.FORBIDDEN.value());

          Map<String, String> error = new HashMap<>();
          error.put("access_token", e.getMessage());
          response.setContentType(MediaType.APPLICATION_JSON_VALUE);
          new ObjectMapper().writeValue(response.getOutputStream(), error);
        }
      } else {
        filterChain.doFilter(request, response);
      }
    }
  }

}
