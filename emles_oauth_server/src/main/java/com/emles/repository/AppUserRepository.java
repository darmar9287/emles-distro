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
     * Method for finding credentials by name.
     * @param name - credentials name.
     * @return found credentials.
     */
    AppUser findByName(String name);
}
