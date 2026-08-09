package org.springframework.security.oauth2.server.authorization;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;

public final class OAuth2TokenStatus {

	private final boolean active;

	private OAuth2TokenStatus(boolean active, Map<String,Object> claims) {
		this.active = active;
		this.claims = claims;
	}

	public boolean isActive() {
		return this.active;
	}

	private final Map<String,Object> claims;

	public static OAuth2TokenStatus inactive() {
		return new OAuth2TokenStatus(false, Collections.emptyMap());
	}

	public static OAuth2TokenStatus active() {
		return new OAuth2TokenStatus(true, Collections.emptyMap());
	}

	public Map<String,Object> getClaims() {
		return this.claims;
	}

	public Set<String> getScopes() {
		Object scope = this.claims.get(OAuth2TokenIntrospectionClaimNames.SCOPE);

		if (scope instanceof Collection<?> collection) {
			return collection.stream()
				.map(Object::toString)
				.collect(Collectors.toSet());
		}

		return Collections.emptySet();
	}

	public Instant getExpiresAt() {
		return (Instant) this.claims.get(OAuth2TokenIntrospectionClaimNames.EXP);
	}

	public Instant getIssuedAt() {
		return (Instant) this.claims.get(OAuth2TokenIntrospectionClaimNames.IAT);
	}

	public Instant getNotBefore() {
		return (Instant) this.claims.get(OAuth2TokenIntrospectionClaimNames.NBF);
	}

	public static Builder withClaims(Map<String,Object> claims) {
		return new Builder(claims);
	}

	public static final class Builder {

		private final Map<String,Object> claims;

		private Builder(Map<String,Object> claims) {
			this.claims = claims;
		}

		public OAuth2TokenStatus build() {
			Object active = claims.get(OAuth2TokenIntrospectionClaimNames.ACTIVE);

			return new OAuth2TokenStatus(
				active instanceof Boolean && (Boolean) active,
				Collections.unmodifiableMap(claims)
			);
		}
	}

}
