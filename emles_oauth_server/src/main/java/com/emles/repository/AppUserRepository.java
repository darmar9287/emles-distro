package com.emles.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.emles.model.AppUser;

/**
 * Repository for Credentials class.
 * @author Dariusz Kulig
 *
 */
public interface AppUserRepository
    extends JpaRepository<AppUser, Long> {

    /**
     * Method for finding app user by name.
     * @param name - user name.
     * @return found user entity.
     */
    AppUser findByName(String name);
    
    /**
     * Method for finding app user by email.
     * @param email - user email.
     * @return found user entity.
     */
    AppUser findByEmail(String email);
}
