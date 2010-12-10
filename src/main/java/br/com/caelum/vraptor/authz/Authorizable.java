package br.com.caelum.vraptor.authz;

import java.util.Set;

public interface Authorizable {
	
	public Set<Role> roles();

}
