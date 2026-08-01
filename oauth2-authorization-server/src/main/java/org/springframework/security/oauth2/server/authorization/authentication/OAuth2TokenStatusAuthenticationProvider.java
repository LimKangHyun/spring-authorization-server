/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenStatus;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation for OAuth 2.0 Token Status.
 *
 * @author Gerardo Roza
 * @author Joe Grandja
 * @since 0.1.1
 * @see OAuth2TokenStatusAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2.1">Section
 * 2.1 Introspection Request</a>
 */
public final class OAuth2TokenStatusAuthenticationProvider implements AuthenticationProvider {

	private final OAuth2AuthorizationService authorizationService;

	public OAuth2TokenStatusAuthenticationProvider(
			OAuth2AuthorizationService authorizationService) {

		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		OAuth2TokenStatusAuthenticationToken tokenStatusAuthentication =
				(OAuth2TokenStatusAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal =
				OAuth2AuthenticationProviderUtils
						.getAuthenticatedClientElseThrowInvalidClient(tokenStatusAuthentication);

		OAuth2Authorization authorization =
				this.authorizationService.findByToken(
						tokenStatusAuthentication.getToken(),
						null);

		if (authorization == null) {
			return new OAuth2TokenStatusAuthenticationToken(
					tokenStatusAuthentication.getToken(),
					clientPrincipal,
					OAuth2TokenStatus.inactive()
			);
		}

		OAuth2Authorization.Token<OAuth2Token> authorizedToken =
				authorization.getToken(tokenStatusAuthentication.getToken());

		if (authorizedToken == null || !authorizedToken.isActive()) {
			return new OAuth2TokenStatusAuthenticationToken(
					tokenStatusAuthentication.getToken(),
					clientPrincipal,
					OAuth2TokenStatus.inactive()
			);
		}

		return new OAuth2TokenStatusAuthenticationToken(
				authorizedToken.getToken().getTokenValue(),
				clientPrincipal,
				OAuth2TokenStatus.active()
		);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2TokenStatusAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
