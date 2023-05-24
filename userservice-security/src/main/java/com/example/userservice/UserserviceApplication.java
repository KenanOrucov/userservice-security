package com.example.userservice;

import com.example.userservice.domain.Role;
import com.example.userservice.domain.User;
import com.example.userservice.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class UserserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserserviceApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}
	@Bean
	CommandLineRunner run(UserService service){
		return args -> {
			service.saveRole(new Role(null, "ROLE_USER"));
			service.saveRole(new Role(null, "ROLE_MANAGER"));
			service.saveRole(new Role(null, "ROLE_ADMIN"));
			service.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

			service.saveUser(new User(null, "Kanan Orujov", "ok", "1234", new ArrayList<>()));
			service.saveUser(new User(null, "Kanan ", "ok2", "1234", new ArrayList<>()));
			service.saveUser(new User(null, " Orujov", "ok3", "1234", new ArrayList<>()));
			service.saveUser(new User(null, "Huseyn", "ok4", "husu", new ArrayList<>()));

			service.addRoleToUSer("ok", "ROLE_USER");
			service.addRoleToUSer("ok2", "ROLE_MANAGER");
			service.addRoleToUSer("ok3", "ROLE_ADMIN");
			service.addRoleToUSer("ok4", "ROLE_SUPER_ADMIN");
			service.addRoleToUSer("ok4", "ROLE_ADMIN");
			service.addRoleToUSer("ok3", "ROLE_MANAGER");

		};
	}
}
