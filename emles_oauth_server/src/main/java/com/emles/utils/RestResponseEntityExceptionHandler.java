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

@ControllerAdvice
public class RestResponseEntityExceptionHandler extends ResponseEntityExceptionHandler {

	@ExceptionHandler({ NoSuchClientException.class })
	public ResponseEntity<?> handleNoSuchClientException(Exception ex, WebRequest request) {
		Map<String, Object> responseMap = new HashMap<>();
		responseMap.put("msg", "Invalid client_id");
		return new ResponseEntity<>(responseMap, HttpStatus.NOT_FOUND);
	}
	
	@ExceptionHandler({ InvalidClientException.class })
	public ResponseEntity<?> handleInvalidClientException(Exception ex, WebRequest request) {
		return new ResponseEntity<>("Please sign in to continue", HttpStatus.UNAUTHORIZED);
	}
	
	@ExceptionHandler({ ClientAlreadyExistsException.class })
	public ResponseEntity<?> handleClientAlreadyExistsException(Exception ex, WebRequest request) {
		return new ResponseEntity<>("Client already exists!", HttpStatus.UNPROCESSABLE_ENTITY);
	}
}
