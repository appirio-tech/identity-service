/**
 * 
 */
package com.appirio.tech.core.service.identity.exception;

/**
 * @author sudo
 *
 */
@SuppressWarnings("serial")
public class AuthenticationException extends Exception {

	public AuthenticationException() {
		super();
	}

	public AuthenticationException(String message, Throwable cause, boolean enableSuppression,
			boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public AuthenticationException(String message, Throwable cause) {
		super(message, cause);
	}

	public AuthenticationException(String message) {
		super(message);
	}

	public AuthenticationException(Throwable cause) {
		super(cause);
	}

}
