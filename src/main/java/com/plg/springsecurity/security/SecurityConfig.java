package com.plg.springsecurity.security;

import java.lang.invoke.VarHandle.AccessMode;

import javax.servlet.Filter;
import javax.swing.text.html.FormSubmitEvent;
import javax.swing.text.html.FormSubmitEvent.MethodType;

import com.plg.springsecurity.filter.CustomAuthentificationFilter;
import com.plg.springsecurity.filter.CustomAuthorizationFilter;

import org.aspectj.weaver.tools.PointcutPrimitive;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import lombok.RequiredArgsConstructor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
// @EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final UserDetailsService userDetailsService;
  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    CustomAuthentificationFilter customAuthentificationFilter = new CustomAuthentificationFilter(
        authenticationManager());
    customAuthentificationFilter.setFilterProcessesUrl("/api/login");
    http.csrf().disable();
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    http.authorizeRequests().antMatchers("/api/login/**", "token/refresh/**").permitAll();
    // http.authorizeRequests().antMatchers(HttpMethod.GET,
    // "/api/user/**").hasAuthority("ROLE_USER");
    // http.authorizeRequests().antMatchers(HttpMethod.POST,
    // "/api/user/save/**").hasAnyAuthority("ROLE_ADMIN");
    // http.authorizeRequests().antMatchers(HttpMethod.GET,
    // "/api/roles/**").hasAnyAuthority("ROLE_ADMIN");
    http.authorizeRequests().anyRequest().authenticated();
    http.addFilter(customAuthentificationFilter);
    http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
  }

  @Bean
  @Override
  protected AuthenticationManager authenticationManager() throws Exception {
    return super.authenticationManager();
  }
}
