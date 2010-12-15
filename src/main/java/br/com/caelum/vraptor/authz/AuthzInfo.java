package br.com.caelum.vraptor.authz;

import br.com.caelum.vraptor.Result;
import br.com.caelum.vraptor.resource.ResourceMethod;

public interface AuthzInfo {

	public Authorizable getAuthorizable();

	public void handleAuthError(Result result);

	public boolean accepts(ResourceMethod method);

}
