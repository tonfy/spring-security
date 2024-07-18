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

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link RequestParameterOneTimeTokenAuthenticationRequestResolver}
 *
 * @author Marcus da Coregio
 */
class RequestParameterOneTimeTokenAuthenticationRequestResolverTests {

	private RequestParameterOneTimeTokenAuthenticationRequestResolver resolver = new RequestParameterOneTimeTokenAuthenticationRequestResolver();

	@Test
	void resolveWhenUsernameParameterExistsThenResolved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("username", "josh");
		OneTimeTokenAuthenticationRequest resolved = this.resolver.resolve(request);
		assertThat(resolved).isNotNull();
		assertThat(resolved.getUsername()).isEqualTo("josh");
	}

	@Test
	void resolveWhenNoUsernameParameterThenNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		OneTimeTokenAuthenticationRequest resolved = this.resolver.resolve(request);
		assertThat(resolved).isNull();
	}

	@Test
	void resolveWhenAnotherParameterAndExistsThenResolved() {
		this.resolver = new RequestParameterOneTimeTokenAuthenticationRequestResolver("my_parameter");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("my_parameter", "josh");
		OneTimeTokenAuthenticationRequest resolved = this.resolver.resolve(request);
		assertThat(resolved).isNotNull();
		assertThat(resolved.getUsername()).isEqualTo("josh");
	}

}
