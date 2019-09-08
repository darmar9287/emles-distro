package com.emles.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.emles.service.AuthorityService;

/**
 * Controller class for listing user authorities.
 * @author Dariusz Kulig
 *
 */
@RestController
@RequestMapping("/authority")
public class AuthorityController {

	/**
	 * authorityService - service for maintaining Authority instances.
	 */
	@Autowired
	private AuthorityService authorityService;

	/**
	 * Endpoint where oauth admin can view authorities.
	 * @return JSON object with list of authorities.
	 */
	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	@RequestMapping(value = "/list", method = RequestMethod.GET)
	public ResponseEntity<?> showAuthorities() {
		return ResponseEntity.ok().body(authorityService.listAuthorities());
	}
}
