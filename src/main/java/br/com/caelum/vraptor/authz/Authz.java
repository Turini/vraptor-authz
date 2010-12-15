package br.com.caelum.vraptor.authz;

import java.util.Set;

import br.com.caelum.vraptor.InterceptionException;
import br.com.caelum.vraptor.Result;
import br.com.caelum.vraptor.authz.annotation.AuthzBypass;
import br.com.caelum.vraptor.core.InterceptorStack;
import br.com.caelum.vraptor.interceptor.Interceptor;
import br.com.caelum.vraptor.resource.ResourceMethod;

public class Authz implements Interceptor {

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
		Set<Role> roles = authInfo.getAuthorizable().roles();
		for (Role role : roles) {
			if (authorizator.isAllowed(role, method)) {
				stack.next(method, resourceInstance);
				return;
			}
		}
		authInfo.handleAuthError(result);
	}

	@Override
	public boolean accepts(ResourceMethod method) {
		if (method.getMethod().isAnnotationPresent(AuthzBypass.class)) {
			return false;
		}
		return true;
	}

}
