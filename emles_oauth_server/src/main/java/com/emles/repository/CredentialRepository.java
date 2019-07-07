package com.emles.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.emles.domain.Credentials;

public interface CredentialRepository extends JpaRepository<Credentials,Long> {
    Credentials findByName(String name);
}