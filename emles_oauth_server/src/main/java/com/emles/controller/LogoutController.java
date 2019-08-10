package com.emles.controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.emles.utils.Utils;

import javax.servlet.http.HttpServletRequest;


/**
 * Controller class for signing out.
 * @author Dariusz Kulig
 *
 */
@RestController
public class LogoutController {
	
    /**
     * tokenStore - used for caching access tokens.
     */
    @Autowired
    private TokenStore tokenStore;

    @RequestMapping(method = RequestMethod.DELETE, value = "/sign_out")
    public ResponseEntity<?> logout(HttpServletRequest request) {
    	String authorization = request.getHeader("Authorization");
    	if (authorization != null && authorization.contains("Bearer")) {
    		String tokenId = authorization.substring("Bearer".length() + 1);
    		OAuth2AccessToken oauthAccessToken = tokenStore.readAccessToken(tokenId);
    		if (oauthAccessToken != null) {
    			Utils.removeTokens(oauthAccessToken, tokenStore);
    		}
    		return ResponseEntity.noContent().build();
    	}
    	return ResponseEntity.badRequest().contentType(MediaType.APPLICATION_JSON).build();
    }
}
