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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

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
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOrigin("http://localhost:4200");  
        config.addAllowedMethod("GET");
        config.addAllowedMethod("POST");
        config.addAllowedMethod("PUT");
        config.addAllowedMethod("DELETE");
        config.addAllowedHeader("*");  
        config.setAllowCredentials(true);  

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return new CorsFilter(source);
    }
	
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
	
	
	@SuppressWarnings("removal")
	@Bean
	public SecurityFilterChain security(HttpSecurity http)throws Exception {
		
		http
		.cors() 
        .and()
		.csrf(csrf -> csrf.disable())
		.authorizeHttpRequests((req) -> {
			req.requestMatchers("/bussiness/register", "/bussiness/login")
			.permitAll()
			.requestMatchers("/company/**")
			.authenticated()
			.anyRequest()
			.authenticated();
		})
		.addFilterBefore(appFilter, UsernamePasswordAuthenticationFilter.class);
		
		return http.build();
		
	}
	
	

}
