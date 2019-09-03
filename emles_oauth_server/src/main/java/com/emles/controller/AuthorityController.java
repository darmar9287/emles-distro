package com.emles.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.emles.service.AuthorityService;

@RestController
@RequestMapping("/authority")
public class AuthorityController {

	@Autowired
	private AuthorityService authorityService;

	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	@RequestMapping(value = "/list", method = RequestMethod.GET)
	public ResponseEntity<?> showAuthorities() {
		return ResponseEntity.ok().body(authorityService.listAuthorities());
	}
}
