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

package org.springframework.security.config.annotation.web.configurers.ott;

import java.util.Collections;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationProvider;
import org.springframework.security.authentication.ott.OneTimeTokenSender;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenAuthenticationConverter;
import org.springframework.security.web.authentication.ott.OneTimeTokenAuthenticationFilter;
import org.springframework.security.web.authentication.ott.OneTimeTokenAuthenticationRequestFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultOneTimeTokenSubmitPageGeneratingFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

public final class OneTimeTokenLoginConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<OneTimeTokenLoginConfigurer<H>, H> {

	private final Log logger = LogFactory.getLog(getClass());

	private final ApplicationContext context;

	private OneTimeTokenService oneTimeTokenService;

	private AuthenticationConverter authenticationConverter = new OneTimeTokenAuthenticationConverter();

	private AuthenticationFailureHandler authenticationFailureHandler;

	private AuthenticationSuccessHandler authenticationSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();

	private OneTimeTokenSender oneTimeTokenSender;

	private String submitPageUrl = "/login/ott";

	private boolean submitPageEnabled = true;

	private String loginProcessingUrl = "/login/ott";

	private String authenticationRequestUrl = "/ott/authenticate";

	private String authenticationRequestRedirectUrl = "/login/ott";

	private AuthenticationProvider authenticationProvider;

	public OneTimeTokenLoginConfigurer(ApplicationContext context) {
		this.context = context;
	}

	@Override
	public void init(H http) {
		AuthenticationProvider authenticationProvider = getAuthenticationProvider(http);
		http.authenticationProvider(postProcess(authenticationProvider));
		configureDefaultLoginPage(http);
	}

	private void configureDefaultLoginPage(H http) {
		DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
			.getSharedObject(DefaultLoginPageGeneratingFilter.class);
		if (loginPageGeneratingFilter == null) {
			return;
		}
		loginPageGeneratingFilter.setOneTimeTokenEnabled(true);
		loginPageGeneratingFilter.setOneTimeTokenAuthenticationRequestUrl(this.authenticationRequestUrl);
		if (this.authenticationFailureHandler == null
				&& StringUtils.hasText(loginPageGeneratingFilter.getLoginPageUrl())) {
			this.authenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler(
					loginPageGeneratingFilter.getLoginPageUrl() + "?error");
		}
	}

	@Override
	public void configure(H http) {
		configureSubmitPage(http);
		configureOttAuthenticationRequestFilter(http);
		configureOttAuthenticationFilter(http);
	}

	private void configureOttAuthenticationFilter(H http) {
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		OneTimeTokenAuthenticationFilter oneTimeTokenAuthenticationFilter = new OneTimeTokenAuthenticationFilter(
				authenticationManager, this.authenticationConverter);
		oneTimeTokenAuthenticationFilter.setRequestMatcher(antMatcher(HttpMethod.POST, this.loginProcessingUrl));
		oneTimeTokenAuthenticationFilter.setFailureHandler(getAuthenticationFailureHandler());
		oneTimeTokenAuthenticationFilter.setSuccessHandler(this.authenticationSuccessHandler);
		http.addFilter(postProcess(oneTimeTokenAuthenticationFilter));
	}

	private void configureOttAuthenticationRequestFilter(H http) {
		OneTimeTokenAuthenticationRequestFilter authenticationRequestFilter = new OneTimeTokenAuthenticationRequestFilter(
				getOneTimeTokenService(http), getOneTimeTokenSender(http));
		authenticationRequestFilter.setRedirectUrl(this.authenticationRequestRedirectUrl);
		authenticationRequestFilter.setRequestMatcher(antMatcher(HttpMethod.POST, this.authenticationRequestUrl));
		http.addFilter(postProcess(authenticationRequestFilter));
	}

	private void configureSubmitPage(H http) {
		if (!this.submitPageEnabled) {
			return;
		}
		DefaultOneTimeTokenSubmitPageGeneratingFilter submitPage = new DefaultOneTimeTokenSubmitPageGeneratingFilter();
		submitPage.setResolveHiddenInputs(this::hiddenInputs);
		submitPage.setRequestMatcher(antMatcher(HttpMethod.GET, this.submitPageUrl));
		submitPage.setLoginProcessingUrl(this.loginProcessingUrl);
		http.addFilter(postProcess(submitPage));
	}

	private AuthenticationProvider getAuthenticationProvider(H http) {
		if (this.authenticationProvider != null) {
			return this.authenticationProvider;
		}
		UserDetailsService userDetailsService = getContext().getBean(UserDetailsService.class);
		this.authenticationProvider = new OneTimeTokenAuthenticationProvider(getOneTimeTokenService(http),
				userDetailsService);
		return this.authenticationProvider;
	}

	/**
	 * Specifies the {@link AuthenticationProvider} to use when authenticating the user.
	 * @param authenticationProvider
	 */
	public OneTimeTokenLoginConfigurer<H> authenticationProvider(AuthenticationProvider authenticationProvider) {
		Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");
		this.authenticationProvider = authenticationProvider;
		return this;
	}

	/**
	 * Specifies the URL that a One-Time Token authentication request will be processed.
	 * Defaults to {@code POST /ott/authenticate}.
	 * @param authenticationRequestUrl
	 */
	public OneTimeTokenLoginConfigurer<H> authenticationRequestUrl(String authenticationRequestUrl) {
		Assert.hasText(authenticationRequestUrl, "authenticationRequestUrl cannot be null or empty");
		this.authenticationRequestUrl = authenticationRequestUrl;
		return this;
	}

	/**
	 * Specifies the URL that the user-agent will be redirected after a successful
	 * One-Time Token authentication. Defaults to {@code POST /login/ott}. If you are
	 * using the default submit page make sure that you also configure
	 * {@link #submitPageUrl(String)} to this same URL.
	 * @param authenticationRequestRedirectUrl
	 */
	public OneTimeTokenLoginConfigurer<H> authenticationRequestRedirectUrl(String authenticationRequestRedirectUrl) {
		Assert.hasText(authenticationRequestRedirectUrl, "authenticationRequestRedirectUrl cannot be null or empty");
		this.authenticationRequestRedirectUrl = authenticationRequestRedirectUrl;
		return this;
	}

	/**
	 * Specifies the URL to process the login request, defaults to {@code /login/ott}.
	 * Only POST requests are processed, for that reason make sure that you pass a valid
	 * CSRF token if CSRF protection is enabled.
	 * @param loginProcessingUrl
	 * @see org.springframework.security.config.annotation.web.builders.HttpSecurity#csrf(Customizer)
	 */
	public OneTimeTokenLoginConfigurer<H> loginProcessingUrl(String loginProcessingUrl) {
		Assert.hasText(loginProcessingUrl, "loginProcessingUrl cannot be null or empty");
		this.loginProcessingUrl = loginProcessingUrl;
		return this;
	}

	/**
	 * Configures whether the default one-time token submit page should be shown. This
	 * will prevent the {@link DefaultOneTimeTokenSubmitPageGeneratingFilter} to be
	 * configured.
	 * @param show
	 */
	public OneTimeTokenLoginConfigurer<H> showSubmitPage(boolean show) {
		this.submitPageEnabled = show;
		return this;
	}

	/**
	 * Sets the URL that the default submit page will be generated. Defaults to
	 * {@code /login/ott}. Note that if you don't want to generate the default submit page
	 * you should use {@link #showSubmitPage(boolean)}.
	 * @param submitPageUrl
	 */
	public OneTimeTokenLoginConfigurer<H> submitPageUrl(String submitPageUrl) {
		Assert.hasText(submitPageUrl, "submitPageUrl cannot be null or empty");
		this.submitPageUrl = submitPageUrl;
		return this;
	}

	/**
	 * Specifies the {@link OneTimeTokenSender} to send the generated {@link OneTimeToken}
	 * to the user
	 * @param oneTimeTokenSender
	 */
	public OneTimeTokenLoginConfigurer<H> oneTimeTokenSender(OneTimeTokenSender oneTimeTokenSender) {
		Assert.notNull(oneTimeTokenSender, "oneTimeTokenSender cannot be null");
		this.oneTimeTokenSender = oneTimeTokenSender;
		return this;
	}

	/**
	 * Configures the {@link OneTimeTokenService} used to generate and consume
	 * {@link OneTimeToken}
	 * @param oneTimeTokenService
	 */
	public OneTimeTokenLoginConfigurer<H> oneTimeTokenService(OneTimeTokenService oneTimeTokenService) {
		Assert.notNull(oneTimeTokenService, "oneTimeTokenService cannot be null");
		this.oneTimeTokenService = oneTimeTokenService;
		return this;
	}

	/**
	 * Use this {@link AuthenticationConverter} when converting incoming requests to an
	 * {@link Authentication}. By default, the {@link OneTimeTokenAuthenticationConverter}
	 * is used.
	 * @param authenticationConverter the {@link AuthenticationConverter} to use
	 */
	public OneTimeTokenLoginConfigurer<H> authenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
		return this;
	}

	/**
	 * Specifies the {@link AuthenticationFailureHandler} to use when authentication
	 * fails. The default is redirecting to "/login?error" using
	 * {@link SimpleUrlAuthenticationFailureHandler}
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} to use
	 * when authentication fails.
	 */
	public OneTimeTokenLoginConfigurer<H> authenticationFailureHandler(
			AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
		return this;
	}

	/**
	 * Specifies the {@link AuthenticationSuccessHandler} to be used. The default is
	 * {@link SavedRequestAwareAuthenticationSuccessHandler} with no additional properties
	 * set.
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler}.
	 */
	public OneTimeTokenLoginConfigurer<H> authenticationSuccessHandler(
			AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
		return this;
	}

	private AuthenticationFailureHandler getAuthenticationFailureHandler() {
		if (this.authenticationFailureHandler != null) {
			return this.authenticationFailureHandler;
		}
		this.authenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler("/login?error");
		return this.authenticationFailureHandler;
	}

	private OneTimeTokenService getOneTimeTokenService(H http) {
		if (this.oneTimeTokenService != null) {
			return this.oneTimeTokenService;
		}
		OneTimeTokenService bean = getBeanOrNull(http, OneTimeTokenService.class);
		if (bean != null) {
			this.oneTimeTokenService = bean;
		}
		else {
			this.logger.debug("Configuring InMemoryOneTimeTokenService for oneTimeTokenLogin()");
			this.oneTimeTokenService = new InMemoryOneTimeTokenService();
		}
		return this.oneTimeTokenService;
	}

	private OneTimeTokenSender getOneTimeTokenSender(H http) {
		if (this.oneTimeTokenSender != null) {
			return this.oneTimeTokenSender;
		}
		OneTimeTokenSender bean = getBeanOrNull(http, OneTimeTokenSender.class);
		if (bean == null) {
			throw new IllegalStateException("A OneTimeTokenSender is required for oneTimeTokenLogin(). "
					+ "Please define a bean or pass an instance to the DSL.");
		}
		this.oneTimeTokenSender = bean;
		return this.oneTimeTokenSender;
	}

	private <C> C getBeanOrNull(H http, Class<C> clazz) {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);
		if (context == null) {
			return null;
		}
		try {
			return context.getBean(clazz);
		}
		catch (NoSuchBeanDefinitionException ex) {
			return null;
		}
	}

	private Map<String, String> hiddenInputs(HttpServletRequest request) {
		CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		return (token != null) ? Collections.singletonMap(token.getParameterName(), token.getToken())
				: Collections.emptyMap();
	}

	public ApplicationContext getContext() {
		return this.context;
	}

}
