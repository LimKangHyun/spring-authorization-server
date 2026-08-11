package org.springframework.security.oauth2.server.authorization.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

public final class OAuth2ClientAuthenticationValidationFilter
		extends OncePerRequestFilter {

	private final RequestMatcher requestMatcher;

	private AuthenticationFailureHandler authenticationFailureHandler;

	public OAuth2ClientAuthenticationValidationFilter(
			RequestMatcher requestMatcher) {
		this.requestMatcher = requestMatcher;
	}


	@Override
	protected void doFilterInternal(
			HttpServletRequest request,
			HttpServletResponse response,
			FilterChain filterChain)
			throws ServletException, IOException {


		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}


		// client authentication validation

		filterChain.doFilter(request, response);
	}
}
