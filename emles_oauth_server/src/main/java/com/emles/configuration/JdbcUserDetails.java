package com.emles.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.emles.model.Credentials;
import com.emles.repository.CredentialRepository;

/**
 * Implementation of User details service.
 * @author Dariusz Kulig
 *
 */
public class JdbcUserDetails implements UserDetailsService {

    /**
     * credentialRepository - repository used to fetch user credentials.
     */
    @Autowired
    private CredentialRepository credentialRepository;

    @Override
    public final UserDetails loadUserByUsername(String username)
        throws UsernameNotFoundException {
        Credentials credentials = credentialRepository.findByName(username);


        if (credentials == null) {
            throw new UsernameNotFoundException("User" + username
                    + "can not be found");
        }

        return new User(
                credentials.getName(),
                credentials.getPassword(),
                credentials.isEnabled(),
                true, true, true,
                credentials.getAuthorities());
    }
}
