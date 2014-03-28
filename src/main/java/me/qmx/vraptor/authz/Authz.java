/**
 *  Copyright 2011 Douglas Campos <qmx@qmx.me>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package me.qmx.vraptor.authz;

import java.util.EnumSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.com.caelum.vraptor.Accepts;
import br.com.caelum.vraptor.AroundCall;
import br.com.caelum.vraptor.Intercepts;
import br.com.caelum.vraptor.Result;
import me.qmx.vraptor.authz.annotation.AuthzBypass;
import br.com.caelum.vraptor.interceptor.SimpleInterceptorStack;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;

import br.com.caelum.vraptor.controller.HttpMethod;
import br.com.caelum.vraptor.controller.ControllerMethod;

/**
 * Default authorization interceptor implementation. Check for situations on the
 * test cases.
 * 
 * @author douglas campos
 * @author guilherme silveira
 */
@Intercepts
@RequestScoped
public class Authz {
	private static final Logger LOGGER = LoggerFactory.getLogger(Authz.class);

	private Authorizator authorizator;
	private AuthzInfo authInfo;
	private Result result;
	private HttpServletRequest request;

	/**
	 * @deprecated cdi eyes only
	 */
	protected Authz() {

	}

	@Inject
	public Authz(Authorizator authorizator, AuthzInfo authInfo, Result result, HttpServletRequest request) {
		this.authorizator = authorizator;
		this.authInfo = authInfo;
		this.result = result;
		this.request = request;
	}

	@Accepts
	public boolean accepts(ControllerMethod method) {
		return !(method.getMethod().isAnnotationPresent(AuthzBypass.class) || isAnnotationPresent(method.getController().getType()));
	}

	@AroundCall
	public void intercept(SimpleInterceptorStack stack) {
		Authorizable authorizable = authInfo.getAuthorizable();
		if (authorizable == null) {
			LOGGER.error("no AuthInfo found!");
			throw new IllegalStateException("No AuthInfo found");
		} else if (isAllowed(authorizable)) {
			stack.next();
		} else {
			authInfo.handleAuthError(result);
		}
	}

	private boolean isAllowed(Authorizable authorizable) {
		String currentURL = getCurrentURL();
		String method = request.getMethod();
		HttpMethod httpMethod = HttpMethod.valueOf(method);
		Set<HttpMethod> httpMethods = EnumSet.of(httpMethod);
		for (Role role : authorizable.roles()) {
			if (authorizator.isAllowed(role, currentURL, httpMethods)) {
				return true;
			}
		}
		return false;
	}

	private String getCurrentURL() {
		String requestURI = request.getRequestURI();
		String contextPath = request.getContextPath();
		return requestURI.replaceFirst(contextPath, "");
	}

	private boolean isAnnotationPresent(Class<?> type) {
		return type.isAnnotationPresent(AuthzBypass.class) || (!type.equals(Object.class) && isAnnotationPresent(type.getSuperclass()));
	}
}
