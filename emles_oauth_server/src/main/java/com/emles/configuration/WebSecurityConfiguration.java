package com.emles.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Configuration for web security.
 * 
 * @author dariusz
 *
 */
@EnableWebSecurity
@Configuration
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

	/**
	 * Bean for password encoder.
	 * 
	 * @return Bcrypt password encoder instance.
	 */
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@Override
	public UserDetailsService userDetailsServiceBean() throws Exception {
		return new JdbcUserDetails();
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web
		.ignoring()
		.antMatchers("/webjars/**", "/resources/**");
	}

	@Override
	protected final void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/login", "/logout.do")
		.permitAll()
		.antMatchers("/**")
		.authenticated()
		.and()
		.formLogin()
		.loginProcessingUrl("/login.do")
		.usernameParameter("username")
		.passwordParameter("password")
		.loginPage("/login")
		.and()
		.logout()
		.logoutRequestMatcher(new AntPathRequestMatcher("/logout.do"))
		.and()
		.userDetailsService(userDetailsServiceBean());
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsServiceBean()).passwordEncoder(passwordEncoder());
	}
}
