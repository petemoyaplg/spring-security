package com.plg.springsecurity.controllers;

import java.net.URI;
import java.util.List;

import com.plg.springsecurity.models.Role;
import com.plg.springsecurity.models.User;
import com.plg.springsecurity.services.UserServiceImp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {
  @Autowired
  private UserServiceImp userServiceImp;

  @GetMapping("users")
  public ResponseEntity<List<User>> getUsers() {
    return ResponseEntity.ok().body(userServiceImp.getUsers());
  }

  @PostMapping("users/save")
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

  @Data
  class RoleToUserForm {
    private String username;
    private String roleName;
  }
}