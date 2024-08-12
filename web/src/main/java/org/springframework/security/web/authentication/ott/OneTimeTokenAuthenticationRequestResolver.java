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

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationRequest;

/**
 * An interface for resolving an {@link OneTimeTokenAuthenticationRequest} based on the
 * provided {@link HttpServletRequest}
 *
 * @author Marcus da Coregio
 * @since 6.4
 */
public interface OneTimeTokenAuthenticationRequestResolver {

	/**
	 * Resolve the {@link OneTimeTokenAuthenticationRequest} from the provided request
	 * @param request
	 * @return the resolved {@link OneTimeTokenAuthenticationRequest} or {@code null}
	 */
	@Nullable
	OneTimeTokenAuthenticationRequest resolve(HttpServletRequest request);

}
