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

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationRequest;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Resolves the {@link OneTimeTokenAuthenticationRequest} by retrieving the username from
 * the request parameter
 *
 * @author Marcus da Coregio
 * @since 6.4
 */
public final class RequestParameterOneTimeTokenAuthenticationRequestResolver
		implements OneTimeTokenAuthenticationRequestResolver {

	private String requestParameter = "username";

	/**
	 * Constructs a new instance that retrieves the username from the request parameter
	 * named {@code username}
	 */
	public RequestParameterOneTimeTokenAuthenticationRequestResolver() {
	}

	/**
	 * Constructs a new instance that looks for the provided request parameter
	 * @param requestParameter the request parameter to retrieve the username, cannot be
	 * empty
	 */
	public RequestParameterOneTimeTokenAuthenticationRequestResolver(String requestParameter) {
		Assert.hasText(requestParameter, "requestParameter cannot be null or empty");
		this.requestParameter = requestParameter;
	}

	@Override
	public OneTimeTokenAuthenticationRequest resolve(HttpServletRequest request) {
		String username = request.getParameter(this.requestParameter);
		if (!StringUtils.hasText(username)) {
			return null;
		}
		return new OneTimeTokenAuthenticationRequest(username);
	}

}
