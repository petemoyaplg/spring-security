package com.plg.springsecurity.services;

import java.util.List;

import com.plg.springsecurity.models.Role;
import com.plg.springsecurity.models.User;
import com.plg.springsecurity.repository.RoleRepository;
import com.plg.springsecurity.repository.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImp implements UserService {

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private RoleRepository roleRepository;

  @Override
  public User saveUser(User user) {
    log.info("Saving new user {} to the database", user.getUsername());
    return this.userRepository.save(user);
  }

  @Override
  public Role saveRole(Role role) {
    log.info("Saving new role {} to the database", role.getName());
    return this.roleRepository.save(role);
  }

  @Override
  public void addRoleToUser(String username, String roleName) {
    User user = this.userRepository.findByUsername(username);
    Role role = this.roleRepository.findByName(roleName);
    user.getRoles().add(role);
  }

  @Override
  public User getUser(String username) {
    return this.userRepository.findByUsername(username);
  }

  @Override
  public List<User> getUsers() {
    return this.userRepository.findAll();
  }

}
