package com.example.demo.security;

import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.csrf().disable().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and().addFilterAfter(new JwtTokenFilter(), UsernamePasswordAuthenticationFilter.class)
		.authorizeRequests().antMatchers(HttpMethod.POST, "/user/**").permitAll()
		.antMatchers(HttpMethod.POST,"/movies/**").hasAuthority("Admin")
		.anyRequest().authenticated();
	}

}
