package me.qmx.vraptor.authz;

import java.util.EnumSet;

import br.com.caelum.vraptor.resource.HttpMethod;

public interface Authorizator {
	
	public boolean isAllowed(Role role, String url,
			EnumSet<HttpMethod> httpMethods);

}
