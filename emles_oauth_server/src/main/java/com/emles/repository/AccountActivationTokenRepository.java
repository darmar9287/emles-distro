package com.emles.repository;

import org.springframework.data.repository.CrudRepository;

import com.emles.model.AccountActivationToken;
import com.emles.model.AppUser;

public interface AccountActivationTokenRepository extends CrudRepository<AccountActivationToken, Integer> {
	AccountActivationToken findByToken(String token);
	AccountActivationToken findByUser(AppUser user);
}