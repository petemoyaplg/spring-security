package com.plg.springsecurity.services;

import java.util.List;

import com.plg.springsecurity.models.Role;
import com.plg.springsecurity.models.User;

public interface UserService {

  User saveUser(User user);

  Role saveRole(Role role);

  void addRoleToUser(String username, String roleName);

  User getUser(String username);

  List<User> getUsers();
}
