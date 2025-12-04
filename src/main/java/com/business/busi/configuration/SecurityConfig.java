package com.business.busi.configuration;

import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.business.busi.service.CustomerService;

import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Autowired
	private AppFilter appFilter;
	
	@Autowired
    private CustomerService customerService;
	
	@Autowired
	private BCryptPasswordEncoder pwdEncoder;
	
	@Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(customerService);
        provider.setPasswordEncoder(pwdEncoder);
        return provider;
    }
	
	@Bean
	public AuthenticationManager authManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}
	
	
	@Bean
	public SecurityFilterChain security(HttpSecurity http)throws Exception {
		
		http
		.csrf(csrf -> csrf.disable())
		.authorizeHttpRequests((req) -> {
			req.requestMatchers("/bussiness/register", "/bussiness/login")
			.permitAll()
			.anyRequest()
			.authenticated();
		})
		.addFilterBefore(appFilter, UsernamePasswordAuthenticationFilter.class);
		
		return http.build();
		
	}
	
	

}
