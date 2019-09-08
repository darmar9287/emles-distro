package com.emles.repository;

import org.springframework.data.repository.CrudRepository;

import com.emles.model.Authority;

/**
 * Repository for Authority class.
 * @author Dariusz Kulig
 *
 */
public interface AuthorityRepository extends CrudRepository<Authority, Long> {

	/**
	 * Method for finding Authority instance by authority name.
	 * @param authority - authority name
	 * @return - found Authority instance.
	 */
	Authority findByAuthority(String authority);
}