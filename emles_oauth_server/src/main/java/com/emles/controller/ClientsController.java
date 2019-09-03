package com.emles.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.emles.configuration.AuthorityPropertyEditor;
import com.emles.configuration.SplitCollectionEditor;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Controller class for maintaining oauth clients.
 * @author Dariusz Kulig
 *
 */
@RestController
@RequestMapping("clients")
public class ClientsController {

	/**
	 * bcryptEncoder - encoder for client details secret
	 */
	@Autowired
	private PasswordEncoder bcryptEncoder;

	/**
	 * clientsDetailsService - Basic, JDBC implementation of the client details service.
	 */
	@Autowired
	private JdbcClientDetailsService clientsDetailsService;

	/**
	 * Spring annotation.
	 * @param binder - web data binder
	 */
	@InitBinder
	public void webBinder(WebDataBinder binder) {
		binder.registerCustomEditor(Collection.class, new SplitCollectionEditor(Set.class, ","));
		binder.registerCustomEditor(GrantedAuthority.class, new AuthorityPropertyEditor());
	}

	/**
	 * Endpoint for listing oauth clients.
	 * @return JSON array with client details
	 */
	@RequestMapping(value = "/list", method = RequestMethod.GET)
	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	public ResponseEntity<?> listClients() {
		return ResponseEntity.ok().body(clientsDetailsService.listClientDetails());
	}

	/**
	 * Endpoint for showing particular oauth client.
	 * @param id - client id.
	 * @return entity with client details response (200).
	 * @throws JSONException
	 */
	@RequestMapping(value = "/show/{client.clientId}", method = RequestMethod.GET)
	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	public ResponseEntity<?> showClient(@PathVariable("client.clientId") String id) throws InvalidClientException {
		return new ResponseEntity<>(clientsDetailsService.loadClientByClientId(id), HttpStatus.OK);
	}

	/**
	 * Endpoint for creating oauth client in db.
	 * @param clientDetails - client details object.
	 * @return JSON object with success message.
	 */
	@RequestMapping(value = "/create", method = RequestMethod.POST)
	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	public ResponseEntity<?> createClient(@RequestBody BaseClientDetails clientDetails) {
		String clientSecretHash = bcryptEncoder.encode(clientDetails.getClientSecret());
		clientDetails.setClientSecret(clientSecretHash);
		clientsDetailsService.addClientDetails(clientDetails);
		Map<String, Object> response = new HashMap<>();
		response.put("msg", "Client has been created");
		return ResponseEntity.ok().body(response);
	}

	/**
	 * Endpoint for editing oauth client in db.
	 * @param clientDetails - client details object.
	 * @return JSON object with success message.
	 */
	@RequestMapping(value = "/edit", method = RequestMethod.PUT)
	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	public ResponseEntity<?> editClient(@RequestBody BaseClientDetails clientDetails) {
		clientsDetailsService.updateClientDetails(clientDetails);
		if (!clientDetails.getClientSecret().isEmpty()) {
			String clientSecretHash = bcryptEncoder.encode(clientDetails.getClientSecret());
			clientsDetailsService.updateClientSecret(clientDetails.getClientId(), clientSecretHash);
		}
		Map<String, Object> response = new HashMap<>();
		response.put("msg", "Client has been updated");
		return ResponseEntity.ok().body(response);
	}

	/**
	 * Endpoint for removing oauth client from db.
	 * @param clientDetails - client details object.
	 * @param id - client id.
	 * @return empty entity response (200).
	 */
	@RequestMapping(value = "/delete/{clientId}", method = RequestMethod.DELETE)
	@PreAuthorize("hasAuthority('ROLE_OAUTH_ADMIN')")
	public ResponseEntity<?> deleteClient(@PathVariable("clientId") String id) {
		clientsDetailsService.removeClientDetails(id);
		return new ResponseEntity<>(HttpStatus.OK);
	}
}
