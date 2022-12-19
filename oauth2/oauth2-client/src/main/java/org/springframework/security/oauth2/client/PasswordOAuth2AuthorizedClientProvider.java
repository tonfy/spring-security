/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.oauth2.client;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.client.endpoint.DefaultPasswordTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An implementation of an {@link OAuth2AuthorizedClientProvider} for the
 * {@link AuthorizationGrantType#PASSWORD password} grant.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizedClientProvider
 * @see DefaultPasswordTokenResponseClient
 * @deprecated The latest OAuth 2.0 Security Best Current Practice disallows the use of
 * the Resource Owner Password Credentials grant. See reference <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-19#section-2.4">OAuth
 * 2.0 Security Best Current Practice.</a>
 */
@Deprecated
public final class PasswordOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {

	private OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient = new DefaultPasswordTokenResponseClient();

	private Duration clockSkew = Duration.ofSeconds(60);

	private Clock clock = Clock.systemUTC();

	/**
	 * Attempt to authorize (or re-authorize) the
	 * {@link OAuth2AuthorizationContext#getClientRegistration() client} in the provided
	 * {@code context}. Returns {@code null} if authorization (or re-authorization) is not
	 * supported, e.g. the client's {@link ClientRegistration#getAuthorizationGrantType()
	 * authorization grant type} is not {@link AuthorizationGrantType#PASSWORD password}
	 * OR the {@link OAuth2AuthorizationContext#USERNAME_ATTRIBUTE_NAME username} and/or
	 * {@link OAuth2AuthorizationContext#PASSWORD_ATTRIBUTE_NAME password} attributes are
	 * not available in the provided {@code context} OR the
	 * {@link OAuth2AuthorizedClient#getAccessToken() access token} is not expired.
	 *
	 * <p>
	 * The following {@link OAuth2AuthorizationContext#getAttributes() context attributes}
	 * are supported:
	 * <ol>
	 * <li>{@link OAuth2AuthorizationContext#USERNAME_ATTRIBUTE_NAME} (required) - a
	 * {@code String} value for the resource owner's username</li>
	 * <li>{@link OAuth2AuthorizationContext#PASSWORD_ATTRIBUTE_NAME} (required) - a
	 * {@code String} value for the resource owner's password</li>
	 * </ol>
	 * @param context the context that holds authorization-specific state for the client
	 * @return the {@link OAuth2AuthorizedClient} or {@code null} if authorization (or
	 * re-authorization) is not supported
	 */
	@Override
	@Nullable
	public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
		Assert.notNull(context, "context cannot be null");
		ClientRegistration clientRegistration = context.getClientRegistration();
		OAuth2AuthorizedClient authorizedClient = context.getAuthorizedClient();
		if (!AuthorizationGrantType.PASSWORD.equals(clientRegistration.getAuthorizationGrantType())) {
			return null;
		}
		String username = context.getAttribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME);
		String password = context.getAttribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME);
		if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
			return null;
		}
		if (authorizedClient != null && !hasTokenExpired(authorizedClient.getAccessToken())) {
			// If client is already authorized and access token is NOT expired than no
			// need for re-authorization
			return null;
		}
		if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken())
				&& authorizedClient.getRefreshToken() != null
				&& !hasTokenExpired(authorizedClient.getRefreshToken())) {
			// If client is already authorized and access token is expired and a refresh
			// token is available, then return and allow
			// RefreshTokenOAuth2AuthorizedClientProvider to handle the refresh
			return null;
		}
		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(clientRegistration, username,
				password);
		OAuth2AccessTokenResponse tokenResponse = getTokenResponse(clientRegistration, passwordGrantRequest);
		return new OAuth2AuthorizedClient(clientRegistration, context.getPrincipal().getName(),
				tokenResponse.getAccessToken(), tokenResponse.getRefreshToken());
	}

	private OAuth2AccessTokenResponse getTokenResponse(ClientRegistration clientRegistration,
			OAuth2PasswordGrantRequest passwordGrantRequest) {
		try {
			return this.accessTokenResponseClient.getTokenResponse(passwordGrantRequest);
		}
		catch (OAuth2AuthorizationException ex) {
			throw new ClientAuthorizationException(ex.getError(), clientRegistration.getRegistrationId(), ex);
		}
	}

	private boolean hasTokenExpired(OAuth2Token token) {
        Instant expires = token.getExpiresAt();
        if (expires == null) {
            return false;
        }
		return this.clock.instant().isAfter(expires.minus(this.clockSkew));
	}

	/**
	 * Sets the client used when requesting an access token credential at the Token
	 * Endpoint for the {@code password} grant.
	 * @param accessTokenResponseClient the client used when requesting an access token
	 * credential at the Token Endpoint for the {@code password} grant
	 */
	public void setAccessTokenResponseClient(
			OAuth2AccessTokenResponseClient<OAuth2PasswordGrantRequest> accessTokenResponseClient) {
		Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
		this.accessTokenResponseClient = accessTokenResponseClient;
	}

	/**
	 * Sets the maximum acceptable clock skew, which is used when checking the
	 * {@link OAuth2AuthorizedClient#getAccessToken() access token} expiry. The default is
	 * 60 seconds.
	 *
	 * <p>
	 * An access token is considered expired if
	 * {@code OAuth2AccessToken#getExpiresAt() - clockSkew} is before the current time
	 * {@code clock#instant()}.
	 * @param clockSkew the maximum acceptable clock skew
	 */
	public void setClockSkew(Duration clockSkew) {
		Assert.notNull(clockSkew, "clockSkew cannot be null");
		Assert.isTrue(clockSkew.getSeconds() >= 0, "clockSkew must be >= 0");
		this.clockSkew = clockSkew;
	}

	/**
	 * Sets the {@link Clock} used in {@link Instant#now(Clock)} when checking the access
	 * token expiry.
	 * @param clock the clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

}
