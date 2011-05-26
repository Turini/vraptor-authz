package me.qmx.vraptor.authz;

import br.com.caelum.vraptor.Result;

public interface AuthzInfo {

	public Authorizable getAuthorizable();

	public void handleAuthError(Result result);

}
