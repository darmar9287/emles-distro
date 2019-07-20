package com.emles.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.configurationprocessor.json.JSONArray;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.boot.configurationprocessor.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.emles.configuration.AuthorityPropertyEditor;
import com.emles.configuration.SplitCollectionEditor;

import java.util.Collection;
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
     * clientsDetailsService - Basic, JDBC implementation
     * of the client details service.
     */
    @Autowired
    private JdbcClientDetailsService clientsDetailsService;

    /**
     * Spring annotation.
     * @param binder - web data binder
     */
    @InitBinder
    public void webBinder(WebDataBinder binder) {
        binder.registerCustomEditor(Collection.class,
                new SplitCollectionEditor(Set.class, ","));
        binder.registerCustomEditor(GrantedAuthority.class,
                new AuthorityPropertyEditor());
    }
    
    /**
     * Endpoint for listing oauth clients.
     * @return JSON array with client details
     */
    @RequestMapping(value = "/list", method = RequestMethod.GET)
    @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
    public ResponseEntity<?> listClients() {
    	return ResponseEntity.ok().body(clientsDetailsService.listClientDetails());
    }
    
    /**
     * Endpoint for showing particular oauth client.
     * @param id - client id.
     * @return entity with client details response (200).
     * @throws JSONException 
     */
    @RequestMapping(value = "/show/{client.clientId}",
            method = RequestMethod.GET)
    @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
    public ResponseEntity<?> showClient(
        @PathVariable("client.clientId") String id) throws InvalidClientException {
        return new ResponseEntity<>(clientsDetailsService.loadClientByClientId(id), HttpStatus.OK);
    }

    /**
     * Endpoint for editing oauth client in db.
     * @param clientDetails - client details object.
     * @param newClient - if present, creates new oauth client.
     * @return view name for this endpoint.
     * @throws JSONException 
     */
    @RequestMapping(value = "/edit", method = RequestMethod.POST)
    @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
    public ResponseEntity<?> editClient(@ModelAttribute BaseClientDetails clientDetails,
            @RequestParam(value = "newClient", required = false) String newClient) throws JSONException {
        
    	if (newClient == null) {
            clientsDetailsService.updateClientDetails(clientDetails);
        } else {
            clientsDetailsService.addClientDetails(clientDetails);
        }

        if (!clientDetails.getClientSecret().isEmpty()) {
            clientsDetailsService
            .updateClientSecret(
                    clientDetails.getClientId(),
                    clientDetails.getClientSecret());
        }
        JSONObject msg = new JSONObject();
        msg.put("msg", "Client data has been updated");
        return ResponseEntity.ok().body(msg);
    }

    /**
     * Endpoint for removing oauth client from db.
     * @param clientDetails - client details object.
     * @param id - client id.
     * @return empty entity response (200).
     */
    @RequestMapping(value = "/delete/{client.clientId}",
            method = RequestMethod.DELETE)
    @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
    public ResponseEntity<?> deleteClient(
        @PathVariable("client.clientId") String id) {

        clientsDetailsService.removeClientDetails(
            clientsDetailsService.loadClientByClientId(id).toString());
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
