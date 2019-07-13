package com.emles.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.emles.configuration.AuthorityPropertyEditor;
import com.emles.configuration.SplitCollectionEditor;

import java.util.Collection;
import java.util.Set;

/**
 * Controller class for maintaining oauth clients.
 * @author Dariusz Kulig
 *
 */
@Controller
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
     * Endpoint for loading oauth client form.
     * @param clientId - client id.
     * @param model - object for storing data in view.
     * @return view name for this endpoint.
     */
    @RequestMapping(value = "/form", method = RequestMethod.GET)
    @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
    public String showEditForm(@RequestParam(value = "client", required = false) String clientId, Model model) {

        ClientDetails clientDetails;
        if (clientId != null) {
            clientDetails = clientsDetailsService
                    .loadClientByClientId(clientId);
        } else {
            clientDetails = new BaseClientDetails();
        }

        model.addAttribute("clientDetails", clientDetails);
        return "form";
    }


    /**
     * Endpoint for editing oauth client in db.
     * @param clientDetails - client details object.
     * @param newClient - if present, creates new oauth client.
     * @return view name for this endpoint.
     */
    @RequestMapping(value = "/edit", method = RequestMethod.POST)
    @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
    public String editClient(@ModelAttribute BaseClientDetails clientDetails,
            @RequestParam(value = "newClient", required = false) String newClient) {
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
        return "redirect:/";
    }

    /**
     * Endpoint for removing oauth client from db.
     * @param clientDetails - client details object.
     * @param id - client id.
     * @return view name for this endpoint.
     */
    @RequestMapping(value = "{client.clientId}/delete",
            method = RequestMethod.POST)
    public String deleteClient(
        @ModelAttribute BaseClientDetails clientDetails,
        @PathVariable("client.clientId") String id) {

        clientsDetailsService.removeClientDetails(
            clientsDetailsService.loadClientByClientId(id).toString());
        return "redirect:/";
    }
}
