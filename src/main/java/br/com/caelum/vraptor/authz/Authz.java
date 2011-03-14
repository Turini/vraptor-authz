package br.com.caelum.vraptor.authz;

import java.util.EnumSet;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.com.caelum.vraptor.InterceptionException;
import br.com.caelum.vraptor.Intercepts;
import br.com.caelum.vraptor.Result;
import br.com.caelum.vraptor.authz.annotation.AuthzBypass;
import br.com.caelum.vraptor.core.InterceptorStack;
import br.com.caelum.vraptor.http.route.Router;
import br.com.caelum.vraptor.interceptor.Interceptor;
import br.com.caelum.vraptor.ioc.RequestScoped;
import br.com.caelum.vraptor.resource.HttpMethod;
import br.com.caelum.vraptor.resource.ResourceMethod;

/**
 * Default authorization interceptor implementation. Check for situations on the
 * test cases.
 * 
 * @author douglas campos
 * @author guilherme silveira
 */
@Intercepts
@RequestScoped
public class Authz implements Interceptor {

	private static final Logger log = LoggerFactory.getLogger(Authz.class);
	private final AuthzInfo authInfo;
	private final Authorizator authorizator;
	private final Result result;
	private final Router router;
	private final HttpServletRequest request;

	public Authz(Authorizator authorizator, AuthzInfo authInfo, Result result, Router router, HttpServletRequest request) {
		this.authorizator = authorizator;
		this.authInfo = authInfo;
		this.result = result;
		this.router = router;
		this.request = request;
	}

	@Override
	public void intercept(InterceptorStack stack, ResourceMethod method, Object resourceInstance) throws InterceptionException {
		Authorizable authorizable = authInfo.getAuthorizable();
		if (authorizable == null) {
			log.error("no AuthInfo found!");
			throw new IllegalStateException("No AuthInfo found");
		} else if (isAllowed(authorizable)) {
			stack.next(method, resourceInstance);
		} else {
			authInfo.handleAuthError(result);
		}
	}

	private boolean isAllowed(Authorizable authorizable) {
		String currentURL = getCurrentURL();
		// EnumSet<HttpMethod> httpMethods =
		// router.allowedMethodsFor(currentURL);
		String method = request.getMethod();
		HttpMethod httpMethod = HttpMethod.valueOf(method);
		EnumSet<HttpMethod> httpMethods = EnumSet.of(httpMethod);
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

	@Override
	public boolean accepts(ResourceMethod method) {
		if (method.getMethod().isAnnotationPresent(AuthzBypass.class) || isAnnotationPresent(method.getResource().getType())) {
			return false;
		}
		return true;
	}

	private boolean isAnnotationPresent(Class<?> type) {
		return type.isAnnotationPresent(AuthzBypass.class) || (!type.equals(Object.class) && isAnnotationPresent(type.getSuperclass()));
	}

}
