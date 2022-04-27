package com.plg.springsecurity.controllers;

import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.plg.springsecurity.models.Role;
import com.plg.springsecurity.models.User;
import com.plg.springsecurity.services.UserServiceImp;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import lombok.Data;
import lombok.RequiredArgsConstructor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class UserController {
  @Autowired
  private UserServiceImp userServiceImp;

  @GetMapping()
  public String welcome() {
    return "Welcom";
  }

  @GetMapping("users")
  public ResponseEntity<List<User>> getUsers() {
    return ResponseEntity.ok().body(userServiceImp.getUsers());
  }

  @GetMapping("roles")
  @PreAuthorize("hasAuthority('ROLE_ADMIN')")
  public ResponseEntity<List<Role>> getRoles() {
    return ResponseEntity.ok().body(userServiceImp.getRoles());
  }

  @PostMapping("user/save")
  public ResponseEntity<User> saveUser(@RequestBody User user) {
    URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("api/user/save").toUriString());
    return ResponseEntity.created(uri).body(userServiceImp.saveUser(user));
  }

  @PostMapping("role/save")
  public ResponseEntity<Role> saveRole(@RequestBody Role role) {
    URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("api/role/save").toUriString());
    return ResponseEntity.created(uri).body(userServiceImp.saveRole(role));
  }

  @PostMapping("role/addtouser")
  public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form) {
    userServiceImp.addRoleToUser(form.getUsername(), form.getRoleName());
    return ResponseEntity.ok().build();
  }

  @GetMapping("token/refresh")
  public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
      try {
        String refreshToken = authorizationHeader.substring("Bearer ".length());
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = jwtVerifier.verify(refreshToken);
        String username = decodedJWT.getSubject();

        User user = userServiceImp.getUser(username);

        String accessToken = JWT.create()
            .withSubject(user.getUsername())
            .withExpiresAt(new Date(System.currentTimeMillis() * 1 * 60 * 1000))
            .withIssuer(request.getRequestURL().toString())
            .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
            .sign(algorithm);

        Map<String, String> headerTokens = new HashMap<>();
        headerTokens.put("access_token", accessToken);
        headerTokens.put("refresh_token", refreshToken);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), headerTokens);
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
      throw new RuntimeException("Refresh token is missing");
    }
  }

  @Data
  class RoleToUserForm {
    private String username;
    private String roleName;
  }
}
