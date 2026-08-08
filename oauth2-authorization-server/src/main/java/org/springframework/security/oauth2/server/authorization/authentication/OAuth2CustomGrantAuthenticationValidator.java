/*
 * Copyright 2020-2024 the original author or authors.
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

import java.util.Set;
import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * A {@code Consumer} providing access to the
 * {@link OAuth2CustomGrantAuthenticationContext} containing an
 * {@link OAuth2CustomGrantAuthenticationToken} and is the default
 * {@link OAuth2CustomGrantAuthenticationProvider#setAuthenticationValidator(Consumer)
 * authentication validator} used for validating specific OAuth 2.0 Client Credentials
 * Grant Request parameters.
 *
 * <p>
 * The default implementation validates
 * {@link OAuth2CustomGrantAuthenticationToken#getScopes()}. If validation fails, an
 * {@link OAuth2AuthenticationException} is thrown.
 *
 * @author Adam Pilling
 * @since 1.3
 * @see OAuth2CustomGrantAuthenticationContext
 * @see OAuth2CustomGrantAuthenticationToken
 * @see OAuth2CustomGrantAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OAuth2CustomGrantAuthenticationValidator
    implements Consumer<OAuth2CustomGrantAuthenticationContext> {

    private static final Log LOGGER = LogFactory.getLog(OAuth2CustomGrantAuthenticationValidator.class);

    /**
     * The default validator for
     * {@link OAuth2CustomGrantAuthenticationToken#getScopes()}.
     */
    public static final Consumer<OAuth2CustomGrantAuthenticationContext> DEFAULT_SCOPE_VALIDATOR = OAuth2CustomGrantAuthenticationValidator::validateScope;

    private final Consumer<OAuth2CustomGrantAuthenticationContext> authenticationValidator = DEFAULT_SCOPE_VALIDATOR;

    @Override
    public void accept(OAuth2CustomGrantAuthenticationContext authenticationContext) {
        this.authenticationValidator.accept(authenticationContext);
    }

    private static void validateScope(OAuth2CustomGrantAuthenticationContext authenticationContext) {
        OAuth2CustomGrantAuthenticationToken customGrantAuthentication = authenticationContext
            .getAuthentication();
        RegisteredClient registeredClient = authenticationContext.getRegisteredClient();

        Set<String> requestedScopes = customGrantAuthentication.getScopes();
        Set<String> allowedScopes = registeredClient.getScopes();
        if (!requestedScopes.isEmpty() && !allowedScopes.containsAll(requestedScopes)) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug(LogMessage.format(
                    "Invalid request: requested scope is not allowed" + " for registered client '%s'",
                    registeredClient.getId()));
            }
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
        }
    }

}
