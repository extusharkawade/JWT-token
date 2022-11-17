package io.getarrays.userservice;

import io.getarrays.userservice.domain.Role;
import io.getarrays.userservice.domain.User;
import io.getarrays.userservice.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
@Slf4j
public class UserserviceApplication {

	public static void main(String[] args) {
		log.error("in UserserviceApplication ");
		SpringApplication.run(UserserviceApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder()
	{
		log.error("in UserserviceApplication passwordEncoder");

		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService)
	{
		log.error("in UserserviceApplication commandLinerunner bean");
		return args -> {
			log.error("in UserserviceApplication  saving roll");
			userService.saveRole(new Role(null,"ROLE_USER"));
			userService.saveRole(new Role(null,"ROLE_MANAGER"));
			userService.saveRole(new Role(null,"ROLE_ADMIN"));
			userService.saveRole(new Role(null,"ROLE_SUPER_ADMIN"));
			log.error("in UserserviceApplication  saving users");

			userService.saveUser(new User(null,"John Travolta","john","1234",new ArrayList<>()));
			userService.saveUser(new User(null,"Tushar Kawade","Tushar","1234",new ArrayList<>()));
			userService.saveUser(new User(null,"Mark Zuckerberg","mark","1234",new ArrayList<>()));
			userService.saveUser(new User(null,"Elon Musk","Elon","1234",new ArrayList<>()));

			log.error("in UserserviceApplication  saving rolls to the users");
			userService.addRoleToUser("john","ROLE_USER");
			userService.addRoleToUser("john","ROLE_MANAGER");
			userService.addRoleToUser("Tushar","ROLE_SUPER_ADMIN");
			userService.addRoleToUser("Tushar","ROLE_MANAGER");
			userService.addRoleToUser("Tushar","ROLE_ADMIN");
			userService.addRoleToUser("mark","ROLE_ADMIN");
			userService.addRoleToUser("Elon","ROLE_MANAGER");
			log.info("in UserserviceApplication  saving done");




		};
	}

}
