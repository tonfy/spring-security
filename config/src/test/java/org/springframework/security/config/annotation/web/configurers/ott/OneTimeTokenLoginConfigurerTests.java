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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenSender;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThatException;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringTestContextExtension.class)
public class OneTimeTokenLoginConfigurerTests {

	public SpringTestContext spring = new SpringTestContext(this);

	@Autowired(required = false)
	MockMvc mvc;

	@Test
	void oneTimeTokenWhenCorrectTokenThenCanAuthenticate() throws Exception {
		this.spring.register(OneTimeTokenDefaultConfig.class).autowire();
		this.mvc.perform(post("/ott/authenticate").param("username", "user").with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/login/ott"));

		String token = TestOneTimeTokenSender.lastToken.getToken();

		this.mvc.perform(post("/login/ott").param("token", token).with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/"), authenticated());
	}

	@Test
	void oneTimeTokenWhenDifferentAuthenticationUrlsThenCanAuthenticate() throws Exception {
		this.spring.register(OneTimeTokenDifferentAuthenticationUrlsConfig.class).autowire();
		this.mvc.perform(post("/authenticationrequesturl").param("username", "user").with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/login/ott"));

		String token = TestOneTimeTokenSender.lastToken.getToken();

		this.mvc.perform(post("/loginprocessingurl").param("token", token).with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/"), authenticated());
	}

	@Test
	void oneTimeTokenWhenCorrectTokenUsedTwiceThenSecondTimeFails() throws Exception {
		this.spring.register(OneTimeTokenDefaultConfig.class).autowire();
		this.mvc.perform(post("/ott/authenticate").param("username", "user").with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/login/ott"));

		String token = TestOneTimeTokenSender.lastToken.getToken();

		this.mvc.perform(post("/login/ott").param("token", token).with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/"), authenticated());

		this.mvc.perform(post("/login/ott").param("token", token).with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/login?error"), unauthenticated());
	}

	@Test
	void oneTimeTokenWhenWrongTokenThenAuthenticationFail() throws Exception {
		this.spring.register(OneTimeTokenDefaultConfig.class).autowire();
		this.mvc.perform(post("/ott/authenticate").param("username", "user").with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/login/ott"));

		String token = "wrong";

		this.mvc.perform(post("/login/ott").param("token", token).with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/login?error"), unauthenticated());
	}

	@Test
	void oneTimeTokenWhenNoOneTimeTokenSenderThenException() {
		assertThatException().isThrownBy(() -> this.spring.register(NoOneTimeTokenSenderConfig.class).autowire())
			.havingRootCause()
			.isInstanceOf(IllegalStateException.class)
			.withMessage(
					"A OneTimeTokenSender is required for oneTimeTokenLogin(). Please define a bean or pass an instance to the DSL.");
	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebSecurity
	@Import(UserDetailsServiceConfig.class)
	static class OneTimeTokenDefaultConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeHttpRequests((authz) -> authz
							.anyRequest().authenticated()
					)
					.oneTimeTokenLogin(Customizer.withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		OneTimeTokenSender oneTimeTokenSender() {
			return new TestOneTimeTokenSender();
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebSecurity
	@Import(UserDetailsServiceConfig.class)
	static class NoOneTimeTokenSenderConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeHttpRequests((authz) -> authz
							.anyRequest().authenticated()
					)
					.oneTimeTokenLogin(Customizer.withDefaults());
			// @formatter:on
			return http.build();
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebSecurity
	@Import(UserDetailsServiceConfig.class)
	static class OneTimeTokenDifferentAuthenticationUrlsConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeHttpRequests((authz) -> authz
							.anyRequest().authenticated()
					)
					.oneTimeTokenLogin((ott) -> ott
							.authenticationRequestUrl("/authenticationrequesturl")
							.loginProcessingUrl("/loginprocessingurl")
					);
			// @formatter:on
			return http.build();
		}

		@Bean
		OneTimeTokenSender oneTimeTokenSender() {
			return new TestOneTimeTokenSender();
		}

	}

	static class TestOneTimeTokenSender implements OneTimeTokenSender {

		private static OneTimeToken lastToken;

		@Override
		public void send(OneTimeToken oneTimeToken) {
			lastToken = oneTimeToken;
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class UserDetailsServiceConfig {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user(), PasswordEncodedUser.admin());
		}

	}

}
