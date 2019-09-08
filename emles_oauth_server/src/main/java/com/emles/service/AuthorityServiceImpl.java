package com.emles.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.emles.model.Authority;
import com.emles.repository.AuthorityRepository;

/**
 * Implementation of AuthorityService interface.
 * @author Dariusz Kulig
 *
 */
@Service
public class AuthorityServiceImpl implements AuthorityService {

	/**
	 * authorityRepository - repository which manages Authority instances in db.
	 */
	@Autowired
	private AuthorityRepository authorityRepository;

	@Transactional
	public List<Authority> listAuthorities() {
		List<Authority> authorities = new ArrayList<>();
		authorityRepository.findAll().forEach(authorities::add);
		return authorities;
	}
}
