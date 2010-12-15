package br.com.caelum.vraptor.authz;

import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import br.com.caelum.vraptor.InterceptionException;
import br.com.caelum.vraptor.Intercepts;
import br.com.caelum.vraptor.Result;
import br.com.caelum.vraptor.authz.annotation.AuthzBypass;
import br.com.caelum.vraptor.core.InterceptorStack;
import br.com.caelum.vraptor.interceptor.Interceptor;
import br.com.caelum.vraptor.ioc.RequestScoped;
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

	public Authz(Authorizator authorizator, AuthzInfo authInfo, Result result) {
		this.authorizator = authorizator;
		this.authInfo = authInfo;
		this.result = result;
	}

	@Override
	public void intercept(InterceptorStack stack, ResourceMethod method,
			Object resourceInstance) throws InterceptionException {
		Authorizable authorizable = authInfo.getAuthorizable();
		if (authorizable == null) {
			log.error("no AuthInfo found!");
			throw new IllegalStateException("No AuthInfo found");
		} else if (isAllowed(method, authorizable)) {
			stack.next(method, resourceInstance);
		} else {
			authInfo.handleAuthError(result);
		}
	}

	private boolean isAllowed(ResourceMethod method, Authorizable authorizable) {
		for (Role role : authorizable.roles()) {
			if (authorizator.isAllowed(role, method)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean accepts(ResourceMethod method) {
		if (method.getMethod().isAnnotationPresent(AuthzBypass.class)) {
			return false;
		}
		return true;
	}

}
