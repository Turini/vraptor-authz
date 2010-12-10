package br.com.caelum.vraptor.authz;

import br.com.caelum.vraptor.resource.ResourceMethod;

public interface Authorizator {
	
	public boolean isAllowed(Role role, ResourceMethod method);

}
