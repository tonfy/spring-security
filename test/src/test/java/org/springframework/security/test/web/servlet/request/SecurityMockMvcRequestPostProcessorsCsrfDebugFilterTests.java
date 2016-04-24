/*
 * Copyright 2002-2014 the original author or authors.
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
package org.springframework.security.test.web.servlet.request;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.test.web.support.WebTestUtils;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration

/**
 * https://github.com/spring-projects/spring-security/pull/3836
 */
public class SecurityMockMvcRequestPostProcessorsCsrfDebugFilterTests {

    @Autowired
	WebApplicationContext wac;

    @Test
    public void shouldFindCookieCsrfTokenRepository() throws Exception {

		// do
		MockHttpServletRequest request = post("/").buildRequest(wac.getServletContext());
		CsrfTokenRepository csrfTokenRepository = WebTestUtils.getCsrfTokenRepository(request);

		// expect
        assertThat(csrfTokenRepository).isInstanceOf(CookieCsrfTokenRepository.class);

    }

	@EnableWebSecurity
	static class Config extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.csrf().csrfTokenRepository(new CookieCsrfTokenRepository());
		}

		@Override
		public void configure(WebSecurity web) throws Exception {
			// enable the debugfilter
			web.debug(true);
		}

		@Bean
		public TheController controller() {
			return new TheController();
		}

		@RestController
		static class TheController {
			@RequestMapping("/")
			String index() {
				return "Hi";
			}
		}
	}
}
