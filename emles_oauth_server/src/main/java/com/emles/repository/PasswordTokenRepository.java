package com.emles.repository;

import org.springframework.data.repository.CrudRepository;

import com.emles.model.AppUser;
import com.emles.model.PasswordResetToken;

public interface PasswordTokenRepository extends CrudRepository<PasswordResetToken, Integer> {
	PasswordResetToken findByToken(String token);

	PasswordResetToken findByUser(AppUser user);
}