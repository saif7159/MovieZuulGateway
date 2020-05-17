package com.example.demo.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class JwtTokenFilter extends OncePerRequestFilter {
	private final Logger log = LoggerFactory.getLogger(JwtTokenFilter.class);
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String header = request.getHeader("Authorization");
		log.info("Authorization header log:"+header);
		if(header==null||!header.contains("Bearer")) {
			filterChain.doFilter(request, response);
			return;
		}
		String token = header.substring(7);
		log.info("token value log: "+token);
		try {
			Claims claims = Jwts.parser().setSigningKey("secret").parseClaimsJws(token).getBody();
			log.info("Inside Claims:"+claims);
			String username = claims.getSubject();
			System.out.println(username);
			log.info("Username from claim"+username);
			log.info("Claimm auth test: "+claims.get("SESSION_TYPE"));
			String role = claims.get("SESSION_TYPE", String.class);
			
			if(username!=null)
			{
				List<String> authorities = new ArrayList<String>();
				authorities.add(role);
				UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, 
						authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
				log.info("auth check"+auth.isAuthenticated());
				log.info("auth level"+auth.getAuthorities());
				SecurityContextHolder.getContext().setAuthentication(auth);
			}
		}catch(Exception e)
		{
			log.info("Username fail"+e.getMessage());
			SecurityContextHolder.clearContext();
		}
		filterChain.doFilter(request, response);
	}

}
