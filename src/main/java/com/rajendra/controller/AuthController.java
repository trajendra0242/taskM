package com.rajendra.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.rajendra.config.JwtProvider;
import com.rajendra.model.User;
import com.rajendra.repository.UserRepository;
import com.rajendra.request.LoginRequest;
import com.rajendra.response.AuthResponse;
import com.rajendra.service.CustomerUserServiceImplementation;

@RestController
@RequestMapping("/auth")
public class AuthController {

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private JwtProvider jwtProvider;
	
	@Autowired
	private CustomerUserServiceImplementation customUserDetails;
	
	
	@PostMapping("/signup")
	public ResponseEntity<AuthResponse> createUserHandler(
			@RequestBody User user) throws Exception{
		String email= user.getEmail();
		String password = user.getPassword();
		String fullName = user.getFullName();
		String role = user.getRole();
		
		User isEmailExist = userRepository.findByEmail(email);
		if(isEmailExist!=null) {
			throw new Exception("Email Is Already Used With Another Account");
		}
		
		String encodedPassword = passwordEncoder.encode(password);
		//createa new user
		User createUser = new User();
		createUser.setEmail(email);
		createUser.setFullName(fullName);
		createUser.setRole(role);
		createUser.setPassword(encodedPassword);
		
		User saveUser = userRepository.save(createUser);
		
//		userRepository.save(saveUser);
		Authentication authentication = new UsernamePasswordAuthenticationToken(email, password);


		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		String token = JwtProvider.generateToken(authentication);
		
		AuthResponse authResponse = new AuthResponse();
		authResponse.setJwt(token);
		authResponse.setMessage("Register Success");
		authResponse.setStatus(true);
		
		
		return new ResponseEntity<AuthResponse>(authResponse,HttpStatus.OK);
		
		
	}
	
	@PostMapping("/signin")
	public ResponseEntity<AuthResponse> signin(@RequestBody LoginRequest loginRequest){
		
		String username = loginRequest.getEmail();
		String password = loginRequest.getPassword();
		
		System.out.println(username +" ------- "+password);
		
		Authentication authentication = authenticate(username,password);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		String token = jwtProvider.generateToken(authentication);
		AuthResponse authResponse = new AuthResponse();
		
		authResponse.setMessage("Login Success");
		authResponse.setJwt(token);
		authResponse.setStatus(true);
		
		return new ResponseEntity<>(authResponse,HttpStatus.OK);
		
	}

	private Authentication authenticate(String username, String password) {
		
		UserDetails userDetails = customUserDetails.loadUserByUsername(username);
		
		System.out.println("sign in userDetails -"+userDetails);
		
		if(userDetails == null) {
			System.out.println("sign in userDetails - null "+userDetails);
			throw new BadCredentialsException("Invalid username or password");
		}
		
		return new UsernamePasswordAuthenticationToken(userDetails,null, userDetails.getAuthorities());
	}
	
	
}
