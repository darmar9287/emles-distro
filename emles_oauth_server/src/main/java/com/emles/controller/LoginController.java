package com.emles.controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import static java.util.Arrays.asList;

/**
 * Controller class for signing in.
 * @author Dariusz Kulig
 *
 */
@Controller
public class LoginController {

    /**
     * clientDetailsService - Basic, JDBC implementation
     * of the client details service.
     */
    @Autowired
    private JdbcClientDetailsService clientDetailsService;

    /**
     * approvalStore - Interface for saving, retrieving and revoking
     * user approvals (per client, per scope).
     */
    @Autowired
    private ApprovalStore approvalStore;

    /**
     * tokenStore - used for caching access tokens.
     */
    @Autowired
    private TokenStore tokenStore;

    /**
     * Method mapping to root path of application.
     * @param model - map of params which are passed to the view.
     * @param principal - signed in user object.
     * @return returns view with attribues passed to view.
     */
    @RequestMapping("/")
    public ModelAndView root(final Map<String, Object> model,
      final Principal principal) {

        List<Approval> approvals = clientDetailsService.listClientDetails()
                .stream()
                .map(clientDetails -> approvalStore.getApprovals(
                        principal.getName(),
                        clientDetails.getClientId()))
                .flatMap(Collection::stream)
                .collect(Collectors.toList());

        model.put("approvals", approvals);
        model.put("clientDetails", clientDetailsService.listClientDetails());
        return new ModelAndView("index", model);
    }

    /**
     * Method for revoking auth token.
     * @param approval - oauth approval list.
     * @return name of template file for revocation of token.
     */
    @RequestMapping(value = "/approval/revoke", method = RequestMethod.POST)
    public String revokeApproval(@ModelAttribute final Approval approval) {

        approvalStore.revokeApprovals(asList(approval));
        tokenStore.findTokensByClientIdAndUserName(approval.getClientId(),
                approval.getUserId())
                .forEach(tokenStore::removeAccessToken);
        return "redirect:/";
    }

    /**
     * Method mapping request to login page.
     * @return name of template file for logout page.
     */
    @RequestMapping("/login")
    public String loginPage() {
        return "login";
    }

    /**
     * Method mapping request to logout page.
     * @param request - HttpServletRequest object with contents of request.
     * @param response - HttpServletResponse object with contents of response.
     * @return name of template file for logout page.
     */
    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String logoutPage(final HttpServletRequest request,
        final HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext()
                .getAuthentication();
        if (auth != null) {
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        return "redirect:/login?logout";
     }
}
