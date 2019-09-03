package com.emles.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.emles.model.AppUser;
import com.emles.repository.AppUserRepository;

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
	private AppUserRepository credentialRepository;

	@Override
	public final UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser appUser = credentialRepository.findByName(username);

		if (appUser == null) {
			throw new UsernameNotFoundException("User" + username + "can not be found");
		}

		return new User(appUser.getName(), appUser.getPassword(), appUser.isEnabled(), true, true, true,
				appUser.getAuthorities());
	}
}
