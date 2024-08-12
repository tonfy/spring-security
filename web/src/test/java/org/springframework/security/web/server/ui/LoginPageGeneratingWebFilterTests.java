/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.web.server.ui;

import java.util.Collections;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;

public class LoginPageGeneratingWebFilterTests {

	@Test
	public void filterWhenLoginWithContextPathThenActionContainsContextPath() throws Exception {
		LoginPageGeneratingWebFilter filter = new LoginPageGeneratingWebFilter();
		filter.setFormLoginEnabled(true);
		MockServerWebExchange exchange = MockServerWebExchange
			.from(MockServerHttpRequest.get("/test/login").contextPath("/test"));
		filter.filter(exchange, (e) -> Mono.empty()).block();
		assertThat(exchange.getResponse().getBodyAsString().block()).contains("action=\"/test/login\"");
	}

	@Test
	public void filterWhenLoginWithNoContextPathThenActionDoesNotContainsContextPath() throws Exception {
		LoginPageGeneratingWebFilter filter = new LoginPageGeneratingWebFilter();
		filter.setFormLoginEnabled(true);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/login"));
		filter.filter(exchange, (e) -> Mono.empty()).block();
		assertThat(exchange.getResponse().getBodyAsString().block()).contains("action=\"/login\"");
	}

	@Test
	void filtersThenRendersPage() {
		String clientName = "Google < > \" \' &";
		LoginPageGeneratingWebFilter filter = new LoginPageGeneratingWebFilter();
		filter.setOauth2AuthenticationUrlToClientName(
				Collections.singletonMap("/oauth2/authorization/google", clientName));
		filter.setFormLoginEnabled(true);
		MockServerWebExchange exchange = MockServerWebExchange
			.from(MockServerHttpRequest.get("/test/login").contextPath("/test"));
		filter.filter(exchange, (e) -> Mono.empty()).block();
		assertThat(exchange.getResponse().getBodyAsString().block()).isEqualTo("""
				<!DOCTYPE html>
				<html lang="en">
				  <head>
				    <meta charset="utf-8">
				    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
				    <meta name="description" content="">
				    <meta name="author" content="">
				    <title>Please sign in</title>
				    <style>
				    /* General layout */
				    body {
				      font-family: system-ui, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
				      background-color: #eee;
				      padding: 40px 0;
				      margin: 0;
				      line-height: 1.5;
				    }
				   \s
				    h2 {
				      margin-top: 0;
				      margin-bottom: 0.5rem;
				      font-size: 2rem;
				      font-weight: 500;
				      line-height: 2rem;
				    }
				   \s
				    .content {
				      margin-right: auto;
				      margin-left: auto;
				      padding-right: 15px;
				      padding-left: 15px;
				      width: 100%;
				      box-sizing: border-box;
				    }
				   \s
				    @media (min-width: 800px) {
				      .content {
				        max-width: 760px;
				      }
				    }
				   \s
				    /* Components */
				    a,
				    a:visited {
				      text-decoration: none;
				      color: #06f;
				    }
				   \s
				    a:hover {
				      text-decoration: underline;
				      color: #003c97;
				    }
				   \s
				    input[type="text"],
				    input[type="password"] {
				      height: auto;
				      width: 100%;
				      font-size: 1rem;
				      padding: 0.5rem;
				      box-sizing: border-box;
				    }
				   \s
				    button {
				      padding: 0.5rem 1rem;
				      font-size: 1.25rem;
				      line-height: 1.5;
				      border: none;
				      border-radius: 0.1rem;
				      width: 100%;
				    }
				   \s
				    button.primary {
				      color: #fff;
				      background-color: #06f;
				    }
				   \s
				    .alert {
				      padding: 0.75rem 1rem;
				      margin-bottom: 1rem;
				      line-height: 1.5;
				      border-radius: 0.1rem;
				      width: 100%;
				      box-sizing: border-box;
				      border-width: 1px;
				      border-style: solid;
				    }
				   \s
				    .alert.alert-danger {
				      color: #6b1922;
				      background-color: #f7d5d7;
				      border-color: #eab6bb;
				    }
				   \s
				    .alert.alert-success {
				      color: #145222;
				      background-color: #d1f0d9;
				      border-color: #c2ebcb;
				    }
				   \s
				    .screenreader {
				      position: absolute;
				      clip: rect(0 0 0 0);
				      height: 1px;
				      width: 1px;
				      padding: 0;
				      border: 0;
				      overflow: hidden;
				    }
				   \s
				    table {
				      width: 100%;
				      max-width: 100%;
				      margin-bottom: 2rem;
				    }
				   \s
				    .table-striped tr:nth-of-type(2n + 1) {
				      background-color: #e1e1e1;
				    }
				   \s
				    td {
				      padding: 0.75rem;
				      vertical-align: top;
				    }
				   \s
				    /* Login / logout layouts */
				    .login-form,
				    .logout-form {
				      max-width: 340px;
				      padding: 0 15px 15px 15px;
				      margin: 0 auto 2rem auto;
				      box-sizing: border-box;
				    }
				    </style>
				  </head>
				  <body>
				    <div class="content">
				      <form class="login-form" method="post" action="/test/login">
				        <h2>Please sign in</h2>

				        <p>
				          <label for="username" class="screenreader">Username</label>
				          <input type="text" id="username" name="username" placeholder="Username" required autofocus>
				        </p>
				        <p>
				          <label for="password" class="screenreader">Password</label>
				          <input type="password" id="password" name="password" placeholder="Password" required>
				        </p>

				        <button type="submit" class="primary">Sign in</button>
				      </form>
				<h2>Login with OAuth 2.0</h2>

				<table class="table table-striped">
				  <tr><td><a href="/test/oauth2/authorization/google">Google &lt; &gt; &quot; &#39; &amp;</a></td></tr>
				</table>
				    </div>
				  </body>
				</html>""");
	}

}
