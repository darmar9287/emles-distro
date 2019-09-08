package com.emles.utils;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Controller advice for exceptions thrown by controllers.
 * @author Dariusz Kulig
 *
 */
@ControllerAdvice
public class RestResponseEntityExceptionHandler extends ResponseEntityExceptionHandler {

	/**
	 * Exception handler for NoSuchClientException. These exceptions are thrown from ClientsController.
	 * @param ex - exception to be handled in this method.
	 * @param request - request from this exception has been thrown.
	 * @return JSON object containing error message.
	 */
	@ExceptionHandler({ NoSuchClientException.class })
	public ResponseEntity<?> handleNoSuchClientException(Exception ex, WebRequest request) {
		Map<String, Object> responseMap = new HashMap<>();
		responseMap.put("msg", "Invalid client_id");
		return new ResponseEntity<>(responseMap, HttpStatus.NOT_FOUND);
	}

	/**
	 * Exception handler for InvalidClientException. These exceptions are thrown from ClientsController when user is not
	 * authorized.
	 * @param ex - exception to be handled in this method.
	 * @param request - request from this exception has been thrown.
	 * @return JSON object containing error message.
	 */
	@ExceptionHandler({ InvalidClientException.class })
	public ResponseEntity<?> handleInvalidClientException(Exception ex, WebRequest request) {
		return new ResponseEntity<>("Please sign in to continue", HttpStatus.UNAUTHORIZED);
	}

	/**
	 * Exception handler for ClientAlreadyExistsException. These exceptions are thrown from ClientsController when user
	 * tries to create the same client.
	 * @param ex - exception to be handled in this method.
	 * @param request - request from this exception has been thrown.
	 * @return JSON object containing error message.
	 */
	@ExceptionHandler({ ClientAlreadyExistsException.class })
	public ResponseEntity<?> handleClientAlreadyExistsException(Exception ex, WebRequest request) {
		return new ResponseEntity<>("Client already exists!", HttpStatus.UNPROCESSABLE_ENTITY);
	}
}
