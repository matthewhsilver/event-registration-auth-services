package com.webage.eventregistration.authservices.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.webage.eventregistration.authservices.domain.TokenRequestData;
import com.webage.eventregistration.authservices.security.Authenticator;
import com.webage.eventregistration.authservices.security.JWTHelper;
import com.webage.eventregistration.authservices.security.JWTUtil;
import com.webage.eventregistration.authservices.security.Token;

@RestController
@RequestMapping("/token")
public class TokenAPI {
	JWTUtil jwtUtil = new JWTHelper();

	@PostMapping(consumes = "application/json")
	public ResponseEntity<?> getToken(@RequestBody TokenRequestData tokenRequestData) {

		String username = tokenRequestData.getUsername();
		String password = tokenRequestData.getPassword();
		String scopes = tokenRequestData.getScopes();

		ResponseEntity<?> response;

		if (username != null && username.length() > 0 && password != null && password.length() > 0
				&& Authenticator.checkPassword(username, password)) {
			Token token = jwtUtil.createToken(scopes);
			response = ResponseEntity.ok(token);
		} else {
			// bad request
			response = ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
		}

		return response;
	}

}
