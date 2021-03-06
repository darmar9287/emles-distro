package com.emles.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;

import java.util.Arrays;

import javax.sql.DataSource;

/**
 * Authorization Server config class.
 * @author Dariusz Kulig
 *
 */
@ConfigurationProperties("application")
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

	/**
	 * redisHost - redis server host name.
	 */
	@Value("${spring.redis.host}")
	private String redisHost;

	/**
	 * redisPort - redis server port number.
	 */
	@Value("${spring.redis.port}")
	private int redisPort;

	/**
	 * authenticationManager - Authentication manager needed for password grant type.
	 */
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private UserDetailsService userDetailsService;

	/**
	 * Redis token store bean.
	 * @return redis connection factory instance.
	 */
	@Bean
	public RedisConnectionFactory redisConnectionFactory() {
		RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();
		config.setHostName(redisHost);
		config.setPort(redisPort);
		return new JedisConnectionFactory(config);
	}

	/**
	 * Oauth data source bean.
	 * @return oauth data source.
	 */
	@Bean
	@ConfigurationProperties(prefix = "spring.datasource")
	public DataSource oauthDataSource() {
		return DataSourceBuilder.create().build();
	}

	/**
	 * JdbcClientDetailsService bean.
	 * @return JdbcClientDetailsService.
	 */
	@Bean
	public JdbcClientDetailsService jdbcClientDetailsService() {
		return new JdbcClientDetailsService(oauthDataSource());
	}

	/**
	 * ApprovalStore bean.
	 * @return JdbcApprovalStore.
	 */
	@Bean
	public ApprovalStore approvalStore() {
		TokenApprovalStore store = new TokenApprovalStore();
		store.setTokenStore(tokenStore());
		return store;
	}

	/**
	 * TokenStoreApprovalHandler bean.
	 * @return TokenStoreUserApprovalHandler instance.
	 */
	@Bean
	public TokenStoreUserApprovalHandler userApprovalHandler() {
		TokenStoreUserApprovalHandler handler = new TokenStoreUserApprovalHandler();
		handler.setTokenStore(tokenStore());
		handler.setRequestFactory(new DefaultOAuth2RequestFactory(jdbcClientDetailsService()));
		handler.setClientDetailsService(jdbcClientDetailsService());
		return handler;
	}

	/**
	 * ProviderManager bean.
	 * @return instance of PreAuthenticatedAuthenticationProvider.
	 */
	@Bean
	public ProviderManager preAuthenticationProvider() {
		PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
		provider.setPreAuthenticatedUserDetailsService(new UserDetailsByNameServiceWrapper<>(userDetailsService));
		return new ProviderManager(Arrays.asList(provider));
	}

	/**
	 * AuthorizationServerTokenServices bean.
	 * @return instance of DefaultTokenServices.
	 */
	@Bean
	public AuthorizationServerTokenServices oauthServerTokenServices() {
		DefaultTokenServices tokenServices = new DefaultTokenServices();
		tokenServices.setClientDetailsService(jdbcClientDetailsService());
		tokenServices.setReuseRefreshToken(false);
		tokenServices.setSupportRefreshToken(true);
		tokenServices.setTokenStore(tokenStore());
		tokenServices.setAuthenticationManager(preAuthenticationProvider());
		return tokenServices;
	}

	/**
	 * Token store bean.
	 * @return JdbcTokenStore.
	 */
	@Bean
	public TokenStore tokenStore() {
		return new RedisTokenStore(redisConnectionFactory());
	}

	/**
	 * Authorization code services bean.
	 * @return jdbc authorization service codes services.
	 */
	@Bean
	public AuthorizationCodeServices authorizationCodeServices() {
		return new JdbcAuthorizationCodeServices(oauthDataSource());
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.withClientDetails(jdbcClientDetailsService());
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
	}

	@Override
	public final void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.approvalStore(approvalStore()).userApprovalHandler(userApprovalHandler())
				.authenticationManager(authenticationManager).authorizationCodeServices(authorizationCodeServices())
				.tokenServices(oauthServerTokenServices());
	}
}
