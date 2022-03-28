package com.plg.springsecurity;

import java.util.ArrayList;

import com.plg.springsecurity.models.Role;
import com.plg.springsecurity.models.User;
import com.plg.springsecurity.services.UserServiceImp;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserServiceImp userService) {
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

			userService.saveUser(new User(null, "John Travolta", "john", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Zill Smith", "will", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Jim Carry", "jim", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Arnold Swchwarzenegger", "arnold", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Kevin Arte", "kevin", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Eva Longoria", "eva", "1234", new ArrayList<>()));

			userService.addRoleToUser("john", "ROLE_USER");
			userService.addRoleToUser("will", "ROLE_USER");
			userService.addRoleToUser("jim", "ROLE_USER");
			userService.addRoleToUser("arnold", "ROLE_USER");
			userService.addRoleToUser("arnold", "ROLE_MANAGER");
			userService.addRoleToUser("kevin", "ROLE_USER");
			userService.addRoleToUser("kevin", "ROLE_ADMIN");
			userService.addRoleToUser("eva", "ROLE_USER");
			userService.addRoleToUser("eva", "ROLE_MANAGER");
			userService.addRoleToUser("eva", "ROLE_SUPER_ADMIN");

		};
	}

}
