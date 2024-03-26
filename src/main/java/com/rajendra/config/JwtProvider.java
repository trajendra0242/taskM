package com.rajendra.config;

import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public class JwtProvider {

	static SecretKey key = Keys.hmacShaKeyFor(JwtConstant.JWT_SECRET.getBytes());

	public static String generateToken(Authentication auth) {
		Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();

		String roles = populateAuthorities(authorities);
		String jwt = Jwts.builder().setIssuedAt(new Date()).setExpiration(new Date(new Date().getTime() + 86400000))
				.claim("email", auth.getName()).claim("authorities", roles).signWith(key).compact();

		return jwt;
	}

	public static String getEmailFromJwtToken(String jwt) {
		jwt = jwt.substring(7);
		Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt).getBody();

		String email = String.valueOf(claims.get("email"));
		return email;
	}

	public static String populateAuthorities(Collection<? extends GrantedAuthority> collection) {
		// Create a set to store unique authority strings
		Set<String> auths = new HashSet<>();

		// Iterate through the collection of GrantedAuthorities
		for (GrantedAuthority authority : collection) {
			// Add the authority string to the set
			auths.add(authority.getAuthority());
		}

		// Join the authority strings with commas and return as a single string
		return String.join(",", auths);
	}
}
