package com.plg.springsecurity.services;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.plg.springsecurity.models.Role;
import com.plg.springsecurity.models.User;
import com.plg.springsecurity.repository.RoleRepository;
import com.plg.springsecurity.repository.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImp implements UserService, UserDetailsService {

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private RoleRepository roleRepository;

  private final PasswordEncoder passwordEncoder;

  @Override
  public User saveUser(User user) {
    log.info("Saving new user {} to the database", user.getUsername());
    user.setPassword(passwordEncoder.encode(user.getPassword()));
    return this.userRepository.save(user);
  }

  @Override
  public Role saveRole(Role role) {
    log.info("Saving new role {} to the database", role.getName());
    return this.roleRepository.save(role);
  }

  @Override
  public void addRoleToUser(String username, String roleName) {
    log.info("Adding role {} to user {}", username, roleName);
    User user = this.userRepository.findByUsername(username);
    Role role = this.roleRepository.findByName(roleName);
    user.getRoles().add(role);
    this.userRepository.save(user);
    log.debug("user updated");
  }

  @Override
  public User getUser(String username) {
    log.info("Fetching user {}", username);
    return this.userRepository.findByUsername(username);
  }

  @Override
  public List<User> getUsers() {
    log.info("Fetching all users");
    return this.userRepository.findAll();
  }

  @Override
  public List<Role> getRoles() {
    log.info("Fetching user all roles");
    return this.roleRepository.findAll();
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = this.userRepository.findByUsername(username);
    if (user == null) {
      log.error("User not found in the database");
      throw new UsernameNotFoundException("User not found in the database");
    } else {
      log.error("User {} found in the database", username);
    }
    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
    user.getRoles().forEach(role -> {
      authorities.add(new SimpleGrantedAuthority(role.getName()));
    });
    return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
  }

}
