package com.emles.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import com.emles.model.AppUser;
import com.emles.model.projection.UserSimplified;

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
    AppUser findByUserDataEmail(String email);
    
    /**
     * Method for finding app user by phone number.
     * @param phone - user phone number.
     * @return found user entity.
     */
    AppUser findByUserDataPhone(String phone);
    
    Page<UserSimplified> findAllBy(Pageable pageable);
    
    UserSimplified findSimplifiedByName(String name);
}
