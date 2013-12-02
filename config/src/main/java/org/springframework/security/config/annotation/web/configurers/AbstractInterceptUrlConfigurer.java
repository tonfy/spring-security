/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configurers;

import java.util.List;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.event.AuthorizationFailureEvent;
import org.springframework.security.access.event.AuthorizedEvent;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

/**
 * A base class for configuring the {@link FilterSecurityInterceptor}.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 *     <li>{@link FilterSecurityInterceptor}</li>
 * </ul>
  *
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are populated to allow other {@link SecurityConfigurer}'s to customize:
 * <ul>
 *     <li>{@link FilterSecurityInterceptor}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 *     <li>{@link org.springframework.security.config.annotation.web.builders.HttpSecurity#getAuthenticationManager()}</li>
 * </ul>
 *
 *
 * @param <C> the AbstractInterceptUrlConfigurer
 * @param <H> the type of {@link HttpSecurityBuilder} that is being configured
 *
 * @author Rob Winch
 * @since 3.2
 * @see ExpressionUrlAuthorizationConfigurer
 * @see UrlAuthorizationConfigurer
 */
abstract class AbstractInterceptUrlConfigurer<C extends AbstractInterceptUrlConfigurer<C,H>, H extends HttpSecurityBuilder<H>> extends
        AbstractHttpConfigurer<C, H>{
    private Boolean filterSecurityInterceptorOncePerRequest;
    private Boolean filterSecurityPublishAuthorizationSuccess;

    private AccessDecisionManager accessDecisionManager;

    @Override
    public void configure(H http) throws Exception {
        FilterInvocationSecurityMetadataSource metadataSource = createMetadataSource(http);
        if(metadataSource == null) {
            return;
        }
        FilterSecurityInterceptor securityInterceptor = createFilterSecurityInterceptor(http, metadataSource, http.getSharedObject(AuthenticationManager.class));
        if(filterSecurityInterceptorOncePerRequest != null) {
            securityInterceptor.setObserveOncePerRequest(filterSecurityInterceptorOncePerRequest);
        }
        if(filterSecurityPublishAuthorizationSuccess != null) {
            securityInterceptor.setPublishAuthorizationSuccess(filterSecurityPublishAuthorizationSuccess);
        }
        securityInterceptor = postProcess(securityInterceptor);
        http.addFilter(securityInterceptor);
        http.setSharedObject(FilterSecurityInterceptor.class, securityInterceptor);
    }

    /**
     * Subclasses should implement this method to provide a {@link FilterInvocationSecurityMetadataSource} for the
     * {@link FilterSecurityInterceptor}.
     *
     * @param http the builder to use
     *
     * @return the {@link FilterInvocationSecurityMetadataSource} to set on the {@link FilterSecurityInterceptor}.
     *         Cannot be null.
     */
    abstract FilterInvocationSecurityMetadataSource createMetadataSource(H http);

    /**
     * Subclasses should implement this method to provide the {@link AccessDecisionVoter} instances used to create the
     * default {@link AccessDecisionManager}
     *
     * @param http the builder to use
     *
     * @return the {@link AccessDecisionVoter} instances used to create the
     *         default {@link AccessDecisionManager}
     */
    @SuppressWarnings("rawtypes")
    abstract List<AccessDecisionVoter> getDecisionVoters(H http);

    abstract class AbstractInterceptUrlRegistry<R extends AbstractInterceptUrlRegistry<R,T>,T> extends AbstractConfigAttributeRequestMatcherRegistry<T> {

        /**
         * Allows setting the {@link AccessDecisionManager}. If none is provided, a default {@l AccessDecisionManager} is
         * created.
         *
         * @param accessDecisionManager the {@link AccessDecisionManager} to use
         * @return  the {@link AbstractInterceptUrlConfigurer} for further customization
         */
        public R accessDecisionManager(
                AccessDecisionManager accessDecisionManager) {
            AbstractInterceptUrlConfigurer.this.accessDecisionManager = accessDecisionManager;
            return getSelf();
        }

        /**
         * Allows setting if the {@link FilterSecurityInterceptor} should be only applied once per request (i.e. if the
         * filter intercepts on a forward, should it be applied again).
         *
         * @param filterSecurityInterceptorOncePerRequest if the {@link FilterSecurityInterceptor} should be only applied
         *                                                once per request
         * @return  the {@link AbstractInterceptUrlConfigurer} for further customization
         */
        public R filterSecurityInterceptorOncePerRequest(
                boolean filterSecurityInterceptorOncePerRequest) {
            AbstractInterceptUrlConfigurer.this.filterSecurityInterceptorOncePerRequest = filterSecurityInterceptorOncePerRequest;
            return getSelf();
        }

        /**
         * Allows setting if the {@link FilterSecurityInterceptor} should send events when authorization is successful.
         * By default only {@link AuthorizationFailureEvent}s  will be published. If you set this property to true,
         * {@link AuthorizedEvent}s will also be published.
         *
         * @param filterSecurityPublishAuthorizationSuccess if the {@link FilterSecurityInterceptor} should send events
         *                                                  when authorization is successful
         * @return  the {@link AbstractInterceptUrlConfigurer} for further customization
         */
        public R filterSecurityPublishAuthorizationSuccess(
                boolean filterSecurityPublishAuthorizationSuccess) {
            AbstractInterceptUrlConfigurer.this.filterSecurityPublishAuthorizationSuccess = filterSecurityPublishAuthorizationSuccess;
            return getSelf();
        }

        /**
         * Returns a reference to the current object with a single suppression of
         * the type
         *
         * @return a reference to the current object
         */
        @SuppressWarnings("unchecked")
        private R getSelf() {
            return (R) this;
        }
    }

    /**
     * Creates the default {@code AccessDecisionManager}
     * @return the default {@code AccessDecisionManager}
     */
    private AccessDecisionManager createDefaultAccessDecisionManager(H http) {
        return new AffirmativeBased(getDecisionVoters(http));
    }

    /**
     * If currently null, creates a default {@link AccessDecisionManager} using
     * {@link #createDefaultAccessDecisionManager()}. Otherwise returns the {@link AccessDecisionManager}.
     *
     * @param http the builder to use
     *
     * @return the {@link AccessDecisionManager} to use
     */
    private AccessDecisionManager getAccessDecisionManager(H http) {
        if (accessDecisionManager == null) {
            accessDecisionManager = createDefaultAccessDecisionManager(http);
        }
        return accessDecisionManager;
    }

    /**
     * Creates the {@link FilterSecurityInterceptor}
     *
     * @param http the builder to use
     * @param metadataSource the {@link FilterInvocationSecurityMetadataSource} to use
     * @param authenticationManager the {@link AuthenticationManager} to use
     * @return the {@link FilterSecurityInterceptor}
     * @throws Exception
     */
    private FilterSecurityInterceptor createFilterSecurityInterceptor(H http, FilterInvocationSecurityMetadataSource metadataSource,
                                                                      AuthenticationManager authenticationManager) throws Exception {
        FilterSecurityInterceptor securityInterceptor = new FilterSecurityInterceptor();
        securityInterceptor.setSecurityMetadataSource(metadataSource);
        securityInterceptor.setAccessDecisionManager(getAccessDecisionManager(http));
        securityInterceptor.setAuthenticationManager(authenticationManager);
        securityInterceptor.afterPropertiesSet();
        return securityInterceptor;
    }
}