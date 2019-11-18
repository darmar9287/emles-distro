package com.emles.integration;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.stereotype.Component;

import com.emles.model.AppUser;
import com.emles.model.Authority;
import com.emles.repository.AccountActivationTokenRepository;
import com.emles.repository.AppUserRepository;
import com.emles.repository.AuthorityRepository;
import com.emles.repository.PasswordTokenRepository;

@Component
public class DBPopulator {

	@Autowired
	private AuthorityRepository authorityRepository;
	
	@Autowired
	private AppUserRepository userRepository;
	
	@Autowired
	private JdbcClientDetailsService clientsDetailsService;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AccountActivationTokenRepository accountActivationTokenRepository;
	
	@Autowired
	private PasswordTokenRepository passwordTokenRepository;
	
	private String productAdminClientId = "integration_test_product_admin";
	
	private String oauthAdminClientId = "integration_test_oauth_admin";
	
	private String resourceAdminClientId = "integration_test_resource_admin";
	
	public void populate() {
		authorityRepository.deleteAll();
		accountActivationTokenRepository.deleteAll();
		passwordTokenRepository.deleteAll();
		userRepository.deleteAll();
		userRepository.flush();
		clientsDetailsService.listClientDetails().forEach(clientDetails -> {
			clientsDetailsService.removeClientDetails(clientDetails.getClientId());
		});
		createAuthorities();
		createUsers();
		createClients();
	}

	private void createClients() {
		Set<String> redirectUri = new HashSet<>();
		redirectUri.add("http://127.0.0.1");
		
		Authority productAdminAuthority = authorityRepository.findByAuthority("ROLE_PRODUCT_ADMIN");
		BaseClientDetails productAdminClient = new BaseClientDetails();
		productAdminClient.setClientId(productAdminClientId);
		productAdminClient.setResourceIds(Arrays.asList("oauth_server_api"));
		productAdminClient.setClientSecret(passwordEncoder.encode("user"));
		productAdminClient.setScope(Arrays.asList("read", "write"));
		productAdminClient.setAuthorizedGrantTypes(Arrays.asList("refresh_token", "password"));
		productAdminClient.setRegisteredRedirectUri(redirectUri);
		productAdminClient.setAuthorities(Arrays.asList(productAdminAuthority));
		productAdminClient.setAccessTokenValiditySeconds(1800);
		productAdminClient.setRefreshTokenValiditySeconds(3600);
		productAdminClient.setAutoApproveScopes(Arrays.asList("true"));
		clientsDetailsService.addClientDetails(productAdminClient);
		
		Authority oauthAdminAuthority = authorityRepository.findByAuthority("ROLE_OAUTH_ADMIN");
		BaseClientDetails oauthAdminClient = new BaseClientDetails();
		oauthAdminClient.setClientId(oauthAdminClientId);
		oauthAdminClient.setResourceIds(Arrays.asList("oauth_server_api"));
		oauthAdminClient.setClientSecret(passwordEncoder.encode("user"));
		oauthAdminClient.setScope(Arrays.asList("read", "write"));
		oauthAdminClient.setAuthorizedGrantTypes(Arrays.asList("password"));
		oauthAdminClient.setRegisteredRedirectUri(redirectUri);
		oauthAdminClient.setAuthorities(Arrays.asList(oauthAdminAuthority));
		oauthAdminClient.setAccessTokenValiditySeconds(30);
		oauthAdminClient.setRefreshTokenValiditySeconds(0);
		oauthAdminClient.setAutoApproveScopes(Arrays.asList("true"));
		clientsDetailsService.addClientDetails(oauthAdminClient);
		
		Authority resourceAdminAuthority = authorityRepository.findByAuthority("ROLE_USER");
		BaseClientDetails resourceAdminClient = new BaseClientDetails();
		resourceAdminClient.setClientId(resourceAdminClientId);
		resourceAdminClient.setResourceIds(Arrays.asList("oauth_server_api"));
		resourceAdminClient.setClientSecret(passwordEncoder.encode("user"));
		resourceAdminClient.setScope(Arrays.asList("read", "write"));
		resourceAdminClient.setAuthorizedGrantTypes(Arrays.asList("refresh_token","password"));
		resourceAdminClient.setRegisteredRedirectUri(redirectUri);
		resourceAdminClient.setAuthorities(Arrays.asList(resourceAdminAuthority));
		resourceAdminClient.setAccessTokenValiditySeconds(30);
		resourceAdminClient.setRefreshTokenValiditySeconds(60);
		resourceAdminClient.setAutoApproveScopes(Arrays.asList("true"));
		clientsDetailsService.addClientDetails(resourceAdminClient);
	}

	private void createUsers() {
		AppUser oauthAdmin = new AppUser();
		oauthAdmin.setEmail("oauth_admin@emles.com");
		oauthAdmin.setEnabled(true);
		oauthAdmin.setLastPasswordResetDate(Date.from(Instant.now()));
		oauthAdmin.setName("oauth_admin");
		oauthAdmin.setPassword(passwordEncoder.encode("user"));
		oauthAdmin.setPhone("700700700");
		Authority oauthAdminAuthority = authorityRepository.findByAuthority("ROLE_OAUTH_ADMIN");
		oauthAdmin.setAuthorities(Arrays.asList(oauthAdminAuthority));
		userRepository.save(oauthAdmin);
		
		AppUser resourceAdmin = new AppUser();
		resourceAdmin.setEmail("resource_admin@emles.com");
		resourceAdmin.setEnabled(true);
		resourceAdmin.setLastPasswordResetDate(Date.from(Instant.now()));
		resourceAdmin.setName("resource_admin");
		resourceAdmin.setPassword(passwordEncoder.encode("user"));
		resourceAdmin.setPhone("700799799");
		Authority resourceAdminAuthority = authorityRepository.findByAuthority("ROLE_USER");
		resourceAdmin.setAuthorities(Arrays.asList(resourceAdminAuthority));
		userRepository.save(resourceAdmin);
		
		AppUser productAdmin = new AppUser();
		productAdmin.setEmail("product_admin@emles.com");
		productAdmin.setEnabled(true);
		productAdmin.setLastPasswordResetDate(Date.from(Instant.now()));
		productAdmin.setName("product_admin");
		productAdmin.setPassword(passwordEncoder.encode("user"));
		productAdmin.setPhone("700800800");
		Authority productAdminAuthority = authorityRepository.findByAuthority("ROLE_PRODUCT_ADMIN");
		productAdmin.setAuthorities(Arrays.asList(productAdminAuthority));
		userRepository.save(productAdmin);
	}

	private void createAuthorities() {
		Authority oauthAdmin = new Authority();
		oauthAdmin.setAuthority("ROLE_OAUTH_ADMIN");
		oauthAdmin.setId(1L);
		Authority user = new Authority();
		user.setAuthority("ROLE_USER");
		user.setId(2L);
		Authority productAdmin = new Authority();
		productAdmin.setAuthority("ROLE_PRODUCT_ADMIN");
		productAdmin.setId(3L);
		authorityRepository.save(oauthAdmin);
		authorityRepository.save(user);
		authorityRepository.save(productAdmin);
	}
}
