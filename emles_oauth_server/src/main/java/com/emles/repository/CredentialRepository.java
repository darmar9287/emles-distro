package com.emles.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.emles.model.Credentials;

/**
 * Repository for Credentials class.
 * @author Dariusz Kulig
 *
 */
public interface CredentialRepository
    extends JpaRepository<Credentials, Long> {

    /**
     * Method for finding credentials by name.
     * @param name - credentials name.
     * @return found credentials.
     */
    Credentials findByName(String name);
}
