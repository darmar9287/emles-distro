package com.emles.repository;

import org.springframework.data.repository.CrudRepository;

import com.emles.model.Authority;

public interface AuthorityRepository extends CrudRepository<Authority, Integer> {
    Authority findByAuthority(String authority);
}