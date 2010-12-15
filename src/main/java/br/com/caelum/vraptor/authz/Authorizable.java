package br.com.caelum.vraptor.authz;

import java.util.Set;

/**
 * Marks agents as authorizables.
 * 
 * @author douglas campos
 */
public interface Authorizable {

	/**
	 * Returns the set of roles that this authorizable agent has. It should
	 * never return null, but an empty set instead.
	 * 
	 * @return the set of roles
	 */
	public Set<Role> roles();

}
