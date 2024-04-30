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

package org.springframework.security.oauth2.client.web.function.client;

import java.util.Map;
import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.RequestMatcher;
import org.springframework.test.web.client.ResponseCreator;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.headerDoesNotExist;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Tests for {@link OAuth2ClientHttpRequestInterceptor}.
 *
 * @author Steve Riesenberg
 */
@ExtendWith(MockitoExtension.class)
public class OAuth2ClientHttpRequestInterceptorTests {

	private static final String REQUEST_URI = "/resources";

	private static final String ERROR_DESCRIPTION = "The request requires higher privileges than provided by the access token.";

	private static final String ERROR_URI = "https://tools.ietf.org/html/rfc6750#section-3.1";

	@Mock
	private OAuth2AuthorizedClientManager authorizedClientManager;

	@Mock
	private OAuth2AuthorizationFailureHandler authorizationFailureHandler;

	@Mock
	private OAuth2AuthorizedClientRepository authorizedClientRepository;

	@Mock
	private SecurityContextHolderStrategy securityContextHolderStrategy;

	@Mock
	private OAuth2AuthorizedClientService authorizedClientService;

	@Captor
	private ArgumentCaptor<OAuth2AuthorizeRequest> authorizeRequestCaptor;

	@Captor
	private ArgumentCaptor<OAuth2AuthorizationException> authorizationExceptionCaptor;

	@Captor
	private ArgumentCaptor<Authentication> authenticationCaptor;

	@Captor
	private ArgumentCaptor<Map<String, Object>> attributesCaptor;

	private ClientRegistration clientRegistration;

	private OAuth2AuthorizedClient authorizedClient;

	private OAuth2ClientHttpRequestInterceptor requestInterceptor;

	private MockRestServiceServer server;

	private RestClient restClient;

	@BeforeEach
	public void setUp() {
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		OAuth2AccessToken accessToken = TestOAuth2AccessTokens.scopes("read", "write");
		this.authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, "user", accessToken);
		this.requestInterceptor = new OAuth2ClientHttpRequestInterceptor(this.authorizedClientManager,
				this.clientRegistration.getRegistrationId());
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
		RequestContextHolder.resetRequestAttributes();
	}

	@Test
	public void constructorWhenAuthorizedClientManagerIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OAuth2ClientHttpRequestInterceptor(null, this.clientRegistration.getRegistrationId()))
			.withMessage("authorizedClientManager cannot be null");
	}

	@Test
	public void constructorWhenClientRegistrationIdIsEmptyThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OAuth2ClientHttpRequestInterceptor(this.authorizedClientManager, ""))
			.withMessage("clientRegistrationId cannot be empty");
	}

	@Test
	public void setAuthorizationFailureHandlerWhenNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.requestInterceptor.setAuthorizationFailureHandler(null))
			.withMessage("authorizationFailureHandler cannot be null");
	}

	@Test
	public void setAuthorizedClientRepositoryWhenNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.requestInterceptor.setAuthorizedClientRepository(null))
			.withMessage("authorizedClientRepository cannot be null");
	}

	@Test
	public void setAuthorizedClientServiceWhenNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.requestInterceptor.setAuthorizedClientService(null))
			.withMessage("authorizedClientService cannot be null");
	}

	@Test
	public void setSecurityContextHolderStrategyWhenNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.requestInterceptor.setSecurityContextHolderStrategy(null))
			.withMessage("securityContextHolderStrategy cannot be null");
	}

	@Test
	public void setPrincipalNameWhenEmptyThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.requestInterceptor.setPrincipalName(""))
			.withMessage("principalName cannot be empty");
	}

	@Test
	public void setPrincipalWhenNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.requestInterceptor.setPrincipal(null))
			.withMessage("principal cannot be null");
	}

	@Test
	public void interceptWhenAnonymousAndAuthorizedThenAuthorizationHeaderSet() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withApplicationJson());
		performRequest();
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal()).isInstanceOf(AnonymousAuthenticationToken.class);
	}

	@Test
	public void interceptWhenAnonymousAndNotAuthorizedThenAuthorizationHeaderNotSet() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class))).willReturn(null);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(headerDoesNotExist(HttpHeaders.AUTHORIZATION))
			.andRespond(withApplicationJson());
		performRequest();
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal()).isInstanceOf(AnonymousAuthenticationToken.class);
	}

	@Test
	public void interceptWhenAuthenticatedAndAuthorizedThenAuthorizationHeaderSet() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withApplicationJson());
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		performRequest();
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal()).isEqualTo(authentication);
	}

	@Test
	public void interceptWhenAuthenticatedAndNotAuthorizedThenAuthorizationHeaderNotSet() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class))).willReturn(null);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(headerDoesNotExist(HttpHeaders.AUTHORIZATION))
			.andRespond(withApplicationJson());
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", null));
		SecurityContextHolder.setContext(securityContext);
		performRequest();
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal()).isInstanceOf(TestingAuthenticationToken.class);
		assertThat(authorizeRequest.getPrincipal().getPrincipal()).isEqualTo("user");
	}

	@Test
	public void interceptWhenAnonymousAndOAuth2ErrorInWwwAuthenticateHeaderThenCallsAuthorizationFailureHandlerWithInsufficientScopeError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withWwwAuthenticateHeader(HttpStatus.OK));
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		performRequest();
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class,
				hasOAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, ERROR_DESCRIPTION));
		assertThat(this.authenticationCaptor.getValue()).isInstanceOf(AnonymousAuthenticationToken.class);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void interceptWhenAuthenticatedAndOAuth2ErrorInWwwAuthenticateHeaderThenCallsAuthorizationFailureHandlerWithInsufficientScopeError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withWwwAuthenticateHeader(HttpStatus.OK));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		performRequest();
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class,
				hasOAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, ERROR_DESCRIPTION));
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(authentication);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void interceptWhenUnauthorizedAndOAuth2ErrorInWwwAuthenticateHeaderThenCallsAuthorizationFailureHandlerWithInsufficientScopeError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withWwwAuthenticateHeader(HttpStatus.UNAUTHORIZED));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class)
			.isThrownBy(() -> this.restClient.get().uri(REQUEST_URI).retrieve().toBodilessEntity())
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class,
				hasOAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, ERROR_DESCRIPTION));
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(authentication);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void interceptWhenForbiddenAndOAuth2ErrorInWwwAuthenticateHeaderThenCallsAuthorizationFailureHandlerWithInsufficientScopeError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withWwwAuthenticateHeader(HttpStatus.FORBIDDEN));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class)
			.isThrownBy(() -> this.restClient.get().uri(REQUEST_URI).retrieve().toBodilessEntity())
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class,
				hasOAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, ERROR_DESCRIPTION));
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(authentication);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void interceptWhenUnauthorizedThenCallsAuthorizationFailureHandlerWithInvalidTokenError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withStatus(HttpStatus.UNAUTHORIZED));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class)
			.isThrownBy(() -> this.restClient.get().uri(REQUEST_URI).retrieve().toBodilessEntity())
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class, hasOAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, null));
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(authentication);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void interceptWhenForbiddenThenCallsAuthorizationFailureHandlerWithInsufficientScopeError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withStatus(HttpStatus.FORBIDDEN));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class)
			.isThrownBy(() -> this.restClient.get().uri(REQUEST_URI).retrieve().toBodilessEntity())
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class, hasOAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, null));
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(authentication);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void interceptWhenInternalServerErrorThenDoesNotCallAuthorizationFailureHandler() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR));
		assertThatExceptionOfType(HttpServerErrorException.class)
			.isThrownBy(() -> this.restClient.get().uri(REQUEST_URI).retrieve().toBodilessEntity())
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
	}

	@Test
	public void interceptWhenAuthorizationExceptionThenCallsAuthorizationFailureHandlerWithException() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		OAuth2AuthorizationException authorizationException = new OAuth2AuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN));
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withException(authorizationException));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
			.isThrownBy(() -> this.restClient.get().uri(REQUEST_URI).retrieve().toBodilessEntity())
			.isEqualTo(authorizationException);
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isEqualTo(authorizationException);
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(authentication);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void interceptWhenUnauthorizedAndAuthorizedClientRepositorySetThenAuthorizedClientRemoved() {
		this.requestInterceptor.setAuthorizedClientRepository(this.authorizedClientRepository);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withStatus(HttpStatus.UNAUTHORIZED));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class)
			.isThrownBy(() -> this.restClient.get().uri(REQUEST_URI).retrieve().toBodilessEntity())
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizedClientRepository).removeAuthorizedClient(this.clientRegistration.getRegistrationId(),
				authentication, request, response);
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizedClientRepository);
	}

	@Test
	public void interceptWhenUnauthorizedAndAuthorizedClientServiceSetThenAuthorizedClientRemoved() {
		this.requestInterceptor.setAuthorizedClientService(this.authorizedClientService);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withStatus(HttpStatus.UNAUTHORIZED));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class)
			.isThrownBy(() -> this.restClient.get().uri(REQUEST_URI).retrieve().toBodilessEntity())
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizedClientService).removeAuthorizedClient(this.clientRegistration.getRegistrationId(),
				authentication.getName());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizedClientService);
	}

	@Test
	public void interceptWhenCustomSecurityContextHolderStrategySetThenUsed() {
		this.requestInterceptor.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		given(this.securityContextHolderStrategy.getContext()).willReturn(securityContext);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withApplicationJson());
		performRequest();
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verify(this.securityContextHolderStrategy).getContext();
		verifyNoMoreInteractions(this.authorizedClientManager);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal()).isEqualTo(authentication);
	}

	@Test
	public void interceptWhenCustomPrincipalNameSetThenUsed() {
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		Authentication authentication = new TestingAuthenticationToken("user", null);
		this.requestInterceptor.setPrincipalName(authentication.getName());

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withApplicationJson());
		performRequest();
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal().getName()).isEqualTo(authentication.getName());
	}

	@Test
	public void interceptWhenCustomPrincipalSetThenUsed() {
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		Authentication authentication = new TestingAuthenticationToken("user", null);
		this.requestInterceptor.setPrincipal(authentication);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withApplicationJson());
		performRequest();
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal()).isEqualTo(authentication);
	}

	@Test
	public void httpRequestWhenAnonymousAndAuthorizedThenAuthorizationHeaderSet() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withDefaults());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withApplicationJson());
		performRequestWithHttpRequest();
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal()).isInstanceOf(AnonymousAuthenticationToken.class);
	}

	@Test
	public void httpRequestWhenAnonymousAndNotAuthorizedThenAuthorizationHeaderNotSet() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class))).willReturn(null);

		bindToRestClient(withDefaults());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(headerDoesNotExist(HttpHeaders.AUTHORIZATION))
			.andRespond(withApplicationJson());
		performRequestWithHttpRequest();
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal()).isInstanceOf(AnonymousAuthenticationToken.class);
	}

	@Test
	public void httpRequestWhenAuthenticatedAndAuthorizedThenAuthorizationHeaderSet() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withDefaults());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withApplicationJson());
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		performRequestWithHttpRequest();
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal()).isEqualTo(authentication);
	}

	@Test
	public void httpRequestWhenAuthenticatedAndNotAuthorizedThenAuthorizationHeaderNotSet() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class))).willReturn(null);

		bindToRestClient(withDefaults());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(headerDoesNotExist(HttpHeaders.AUTHORIZATION))
			.andRespond(withApplicationJson());
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		performRequestWithHttpRequest();
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal()).isEqualTo(authentication);
	}

	@Test
	public void errorHandlerWhenAnonymousAndOAuth2ErrorInWwwAuthenticateHeaderThenCallsAuthorizationFailureHandlerWithInsufficientScopeError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withDefaults());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withWwwAuthenticateHeader(HttpStatus.UNAUTHORIZED));
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class).isThrownBy(this::performRequestWithHttpRequest)
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class,
				hasOAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, ERROR_DESCRIPTION));
		assertThat(this.authenticationCaptor.getValue()).isInstanceOf(AnonymousAuthenticationToken.class);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void errorHandlerWhenAuthenticatedAndOAuth2ErrorInWwwAuthenticateHeaderThenCallsAuthorizationFailureHandlerWithInsufficientScopeError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withDefaults());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withWwwAuthenticateHeader(HttpStatus.UNAUTHORIZED));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class).isThrownBy(this::performRequestWithHttpRequest)
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class,
				hasOAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, ERROR_DESCRIPTION));
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(authentication);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void errorHandlerWhenUnauthorizedAndOAuth2ErrorInWwwAuthenticateHeaderThenCallsAuthorizationFailureHandlerWithInsufficientScopeError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withDefaults());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withWwwAuthenticateHeader(HttpStatus.UNAUTHORIZED));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class).isThrownBy(this::performRequestWithHttpRequest)
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class,
				hasOAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, ERROR_DESCRIPTION));
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(authentication);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void errorHandlerWhenForbiddenAndOAuth2ErrorInWwwAuthenticateHeaderThenCallsAuthorizationFailureHandlerWithInsufficientScopeError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withDefaults());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withWwwAuthenticateHeader(HttpStatus.FORBIDDEN));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class).isThrownBy(this::performRequestWithHttpRequest)
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class,
				hasOAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, ERROR_DESCRIPTION));
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(authentication);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void errorHandlerWhenUnauthorizedThenCallsAuthorizationFailureHandlerWithInvalidTokenError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withDefaults());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withStatus(HttpStatus.UNAUTHORIZED));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class).isThrownBy(this::performRequestWithHttpRequest)
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class, hasOAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, null));
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(authentication);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void errorHandlerWhenForbiddenThenCallsAuthorizationFailureHandlerWithInsufficientScopeError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withDefaults());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withStatus(HttpStatus.FORBIDDEN));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class).isThrownBy(this::performRequestWithHttpRequest)
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class, hasOAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, null));
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(authentication);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void errorHandlerWhenInternalServerErrorThenDoesNotCallAuthorizationFailureHandler() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withDefaults());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpServerErrorException.class).isThrownBy(this::performRequestWithHttpRequest)
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
	}

	@Test
	public void errorHandlerWhenAuthorizationExceptionThenDoesNotCallAuthorizationFailureHandler() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withDefaults());
		OAuth2AuthorizationException authorizationException = new OAuth2AuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN));
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withException(authorizationException));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(OAuth2AuthorizationException.class).isThrownBy(this::performRequestWithHttpRequest)
			.isEqualTo(authorizationException);
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
	}

	@Test
	public void errorHandlerWhenUnauthorizedAndAuthorizedClientRepositorySetThenAuthorizedClientRemoved() {
		this.requestInterceptor.setAuthorizedClientRepository(this.authorizedClientRepository);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withDefaults());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withStatus(HttpStatus.UNAUTHORIZED));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class).isThrownBy(this::performRequestWithHttpRequest)
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizedClientRepository).removeAuthorizedClient(this.clientRegistration.getRegistrationId(),
				authentication, request, response);
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizedClientRepository);
	}

	@Test
	public void errorHandlerWhenUnauthorizedAndAuthorizedClientServiceSetThenAuthorizedClientRemoved() {
		this.requestInterceptor.setAuthorizedClientService(this.authorizedClientService);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withDefaults());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withStatus(HttpStatus.UNAUTHORIZED));
		Authentication authentication = new TestingAuthenticationToken("user", null);
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class).isThrownBy(this::performRequestWithHttpRequest)
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizedClientService).removeAuthorizedClient(this.clientRegistration.getRegistrationId(),
				authentication.getName());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizedClientService);
	}

	private void bindToRestClient(Consumer<RestClient.Builder> customizer) {
		RestClient.Builder builder = RestClient.builder();
		customizer.accept(builder);
		this.server = MockRestServiceServer.bindTo(builder).build();
		this.restClient = builder.build();
	}

	private static Consumer<RestClient.Builder> withDefaults() {
		return (builder) -> {
		};
	}

	private Consumer<RestClient.Builder> withRequestInterceptor() {
		return (builder) -> builder.requestInterceptor(this.requestInterceptor);
	}

	private static RequestMatcher hasAuthorizationHeader(OAuth2AccessToken accessToken) {
		String tokenType = accessToken.getTokenType().getValue();
		String tokenValue = accessToken.getTokenValue();
		return header(HttpHeaders.AUTHORIZATION, "%s %s".formatted(tokenType, tokenValue));
	}

	private static ResponseCreator withApplicationJson() {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		return withSuccess().headers(headers).body("{}");
	}

	private static ResponseCreator withWwwAuthenticateHeader(HttpStatus httpStatus) {
		String wwwAuthenticateHeader = "Bearer error=\"insufficient_scope\", "
				+ "error_description=\"The request requires higher privileges than provided by the access token.\", "
				+ "error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\"";
		HttpHeaders headers = new HttpHeaders();
		headers.set(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticateHeader);
		return withStatus(httpStatus).headers(headers);
	}

	private static ResponseCreator withException(OAuth2AuthorizationException ex) {
		return (request) -> {
			throw ex;
		};
	}

	private void performRequest() {
		this.restClient.get().uri(REQUEST_URI).retrieve().toBodilessEntity();
	}

	private void performRequestWithHttpRequest() {
		this.restClient.get()
			.uri(REQUEST_URI)
			.httpRequest(this.requestInterceptor.httpRequest())
			.retrieve()
			.onStatus(this.requestInterceptor.errorHandler())
			.toBodilessEntity();
	}

	private Consumer<ClientAuthorizationException> hasOAuth2Error(String errorCode, String errorDescription) {
		return (ex) -> {
			assertThat(ex.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
			assertThat(ex.getError().getErrorCode()).isEqualTo(errorCode);
			assertThat(ex.getError().getDescription()).isEqualTo(errorDescription);
			assertThat(ex.getError().getUri()).isEqualTo(ERROR_URI);
			assertThat(ex).hasNoCause();
			assertThat(ex).hasMessageContaining(errorCode);
		};
	}

}
