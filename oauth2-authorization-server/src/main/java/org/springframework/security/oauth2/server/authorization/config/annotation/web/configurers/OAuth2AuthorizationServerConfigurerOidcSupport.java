/*
 * Copyright 2020-2025 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.util.function.Consumer;

import org.springframework.context.ApplicationListener;
import org.springframework.context.event.GenericApplicationListenerAdapter;
import org.springframework.context.event.SmartApplicationListener;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.context.DelegatingApplicationListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

/**
 * Provides OpenID Connect specific support for
 * {@link OAuth2AuthorizationServerConfigurer}.
 *
 * @author Joe Grandja
 */
final class OAuth2AuthorizationServerConfigurerOidcSupport {

	void init(HttpSecurity httpSecurity, OAuth2AuthorizationServerConfigurer configurer) {

		if (configurer.getConfigurer(OidcConfigurer.class) != null) {
			initSessionRegistry(httpSecurity);

			SessionRegistry sessionRegistry = httpSecurity.getSharedObject(SessionRegistry.class);

			OAuth2AuthorizationEndpointConfigurer authorizationEndpointConfigurer = configurer
					.getConfigurer(OAuth2AuthorizationEndpointConfigurer.class);

			authorizationEndpointConfigurer.setSessionAuthenticationStrategy(
					(authentication, request, response) -> {
						if (authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication) {

							if (authorizationCodeRequestAuthentication.getScopes()
									.contains(OidcScopes.OPENID)) {

								if (sessionRegistry.getSessionInformation(request.getSession().getId()) == null) {

									sessionRegistry.registerNewSession(request.getSession().getId(),
											((Authentication) authorizationCodeRequestAuthentication
													.getPrincipal()).getPrincipal());
								}
							}
						}
					});
		}
		else {
			Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> oidcAuthenticationRequestValidator = (
					authenticationContext) -> {

				OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = authenticationContext
						.getAuthentication();

				if (authorizationCodeRequestAuthentication.getScopes().contains(OidcScopes.OPENID)) {

					OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE,
							"OpenID Connect 1.0 authentication requests are restricted.",
							"https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1");

					throw new OAuth2AuthorizationCodeRequestAuthenticationException(error,
							authorizationCodeRequestAuthentication);
				}
			};

			OAuth2AuthorizationEndpointConfigurer authorizationEndpointConfigurer = configurer
					.getConfigurer(OAuth2AuthorizationEndpointConfigurer.class);

			authorizationEndpointConfigurer
					.addAuthorizationCodeRequestAuthenticationValidator(oidcAuthenticationRequestValidator);

			OAuth2PushedAuthorizationRequestEndpointConfigurer pushedAuthorizationRequestEndpointConfigurer = configurer
					.getConfigurer(OAuth2PushedAuthorizationRequestEndpointConfigurer.class);

			if (pushedAuthorizationRequestEndpointConfigurer != null) {
				pushedAuthorizationRequestEndpointConfigurer
						.addAuthorizationCodeRequestAuthenticationValidator(oidcAuthenticationRequestValidator);
			}
		}
	}

	private static void initSessionRegistry(HttpSecurity httpSecurity) {
		SessionRegistry sessionRegistry = OAuth2ConfigurerUtils.getOptionalBean(httpSecurity, SessionRegistry.class);

		if (sessionRegistry == null) {
			sessionRegistry = new SessionRegistryImpl();
			registerDelegateApplicationListener(httpSecurity, (SessionRegistryImpl) sessionRegistry);
		}

		httpSecurity.setSharedObject(SessionRegistry.class, sessionRegistry);
	}

	private static void registerDelegateApplicationListener(HttpSecurity httpSecurity,
			ApplicationListener<?> delegate) {

		DelegatingApplicationListener delegatingApplicationListener = OAuth2ConfigurerUtils
				.getOptionalBean(httpSecurity, DelegatingApplicationListener.class);

		if (delegatingApplicationListener == null) {
			return;
		}

		SmartApplicationListener smartListener = new GenericApplicationListenerAdapter(delegate);
		delegatingApplicationListener.addListener(smartListener);
	}

}
