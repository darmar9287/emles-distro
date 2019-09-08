package com.emles.repository;

import org.springframework.data.repository.CrudRepository;

import com.emles.model.AccountActivationToken;
import com.emles.model.AppUser;

/**
 * Repository for AccountActivationToken class.
 * @author Dariusz Kulig
 *
 */
public interface AccountActivationTokenRepository extends CrudRepository<AccountActivationToken, Integer> {
	/**
	 * Method used for finding activation token instance by token string value.
	 * @param token - string value used to be found in db.
	 * @return - found account activation token instance.
	 */
	AccountActivationToken findByToken(String token);

	/**
	 * Method used for finding activation token instance by given user id.
	 * @param user - user instance with id used to be found in db.
	 * @return - found account activation token instance.
	 */
	AccountActivationToken findByUser(AppUser user);
}