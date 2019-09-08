package com.emles.service;

import java.util.List;

import com.emles.model.Authority;

/**
 * Interface with business logic for Autority model.
 * @author Dariusz Kulig
 *
 */
public interface AuthorityService {
	/**
	 * Method for listing authorities.
	 * @return List containing authority objects.
	 */
	List<Authority> listAuthorities();
}
