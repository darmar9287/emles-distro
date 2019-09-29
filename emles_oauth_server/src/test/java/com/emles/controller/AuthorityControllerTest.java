package com.emles.controller;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import com.emles.model.Authority;
import com.emles.repository.AppUserRepository;
import com.emles.service.AuthorityService;

@RunWith(SpringRunner.class)
@WebMvcTest(controllers = { AuthorityController.class })
public class AuthorityControllerTest {

	@Autowired
	private MockMvc mvc;

	@MockBean
	private AuthorityService authorityService;

	@MockBean
	private AppUserRepository appUserRepository;

	@Test
	@WithMockUser(username = "oauth_admin", authorities = { "ROLE_OAUTH_ADMIN" })
	public void testGetListOfAuthorities() throws Exception {
		when(authorityService.listAuthorities()).thenReturn(new ArrayList<Authority>());
		mvc.perform(get("/authority/list")).andExpect(status().is2xxSuccessful());
		verify(authorityService, times(1)).listAuthorities();
	}

	@Test
	@WithMockUser(username = "resource_admin", authorities = { "ROLE_RESOURCE_ADMIN" })
	public void testGetListOfAuthoritiesReturns403ForResourceAdmin() throws Exception {
		mvc.perform(get("/authority/list")).andExpect(status().is(403));
		verify(authorityService, times(0)).listAuthorities();
	}

	@Test
	@WithMockUser(username = "user", authorities = { "ROLE_USER" })
	public void testGetListOfAuthoritiesReturns403ForUser() throws Exception {
		mvc.perform(get("/authority/list")).andExpect(status().is(403));
		verify(authorityService, times(0)).listAuthorities();
	}
}
