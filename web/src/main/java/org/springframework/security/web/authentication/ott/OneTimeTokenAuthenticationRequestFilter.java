/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.authentication.ott;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationRequest;
import org.springframework.security.authentication.ott.OneTimeTokenSender;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Filter that process a One-Time Token authentication request. By default, the filter
 * listen to {@code POST} requests to {@code /ott/authenticate}. The
 * {@link #authenticationRequestResolver} resolves the needed information from the request
 * and the {@link #oneTimeTokenService} generates the {@link OneTimeToken}.
 *
 * @author Marcus da Coregio
 * @since 6.4
 * @see OneTimeTokenService
 */
public class OneTimeTokenAuthenticationRequestFilter extends OncePerRequestFilter {

	private final OneTimeTokenService oneTimeTokenService;

	private final OneTimeTokenSender oneTimeTokenSender;

	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private RequestMatcher requestMatcher = new AntPathRequestMatcher("/ott/authenticate", "POST");

	private OneTimeTokenAuthenticationRequestResolver authenticationRequestResolver = new RequestParameterOneTimeTokenAuthenticationRequestResolver();

	private String redirectUrl = "/login/ott";

	public OneTimeTokenAuthenticationRequestFilter(OneTimeTokenService oneTimeTokenService,
			OneTimeTokenSender oneTimeTokenSender) {
		Assert.notNull(oneTimeTokenService, "oneTimeTokenService cannot be null");
		Assert.notNull(oneTimeTokenSender, "oneTimeTokenSender cannot be null");
		this.oneTimeTokenService = oneTimeTokenService;
		this.oneTimeTokenSender = oneTimeTokenSender;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}
		OneTimeTokenAuthenticationRequest authenticationRequest = this.authenticationRequestResolver.resolve(request);
		if (authenticationRequest == null) {
			filterChain.doFilter(request, response);
			return;
		}
		OneTimeToken ott = this.oneTimeTokenService.generate(authenticationRequest);
		this.oneTimeTokenSender.send(ott);
		this.redirectStrategy.sendRedirect(request, response, this.redirectUrl);
	}

	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	/**
	 * Sets the {@link OneTimeTokenAuthenticationRequestResolver} to use, defaults to
	 * {@link RequestParameterOneTimeTokenAuthenticationRequestResolver}
	 * @param authenticationRequestResolver
	 */
	public void setAuthenticationRequestResolver(
			OneTimeTokenAuthenticationRequestResolver authenticationRequestResolver) {
		Assert.notNull(authenticationRequestResolver, "authenticationRequestResolver cannot be null");
		this.authenticationRequestResolver = authenticationRequestResolver;
	}

	/**
	 * Sets the {@link RedirectStrategy} to use
	 * @param redirectStrategy
	 */
	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		this.redirectStrategy = redirectStrategy;
	}

	/**
	 * The redirect url to be passed to the {@link RedirectStrategy}
	 * @param redirectUrl
	 */
	public void setRedirectUrl(String redirectUrl) {
		this.redirectUrl = redirectUrl;
	}

}
