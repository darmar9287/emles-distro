package com.emles.service;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.junit4.SpringRunner;

import com.emles.model.Authority;
import com.emles.repository.AuthorityRepository;

@RunWith(SpringRunner.class)
public class AuthorityServiceTest {

	@TestConfiguration
	static class AuthorityServiceContextConfiguration {
		@Bean
		public AuthorityService authorityService() {
			return new AuthorityServiceImpl();
		}
	}

	@Autowired
	private AuthorityService authorityService;

	@MockBean
	private AuthorityRepository authorityRepository;

	@Test
	public void testListAuthorities() {
		List<Authority> authorities = new ArrayList<>();
		when(authorityRepository.findAll()).thenReturn(authorities);
		authorityService.listAuthorities();
		verify(authorityRepository, times(1)).findAll();
	}
}
