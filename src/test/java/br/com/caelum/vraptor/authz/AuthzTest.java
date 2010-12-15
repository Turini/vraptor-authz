package br.com.caelum.vraptor.authz;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import br.com.caelum.vraptor.Result;
import br.com.caelum.vraptor.authz.annotation.AuthzBypass;
import br.com.caelum.vraptor.core.InterceptorStack;
import br.com.caelum.vraptor.resource.ResourceMethod;

public class AuthzTest {

	@Mock
	private ResourceMethod resourceMethod;
	
	@Mock
	private ResourceMethod bypassedResourceMethod;

	@Mock
	private InterceptorStack stack;

	@Mock
	private Result result;

	@Mock
	private Authorizator authorizator;

	@Mock
	private Authorizable authorizable;

	@Mock
	private AuthzInfo authInfo;

	@Mock
	private Role admin;

	@Mock
	private Role user;

	private Authz interceptor;
	private Set<Role> allRoles;
	private Set<Role> noRoles;

	@Before
	public void setUp() throws Exception {
		MockitoAnnotations.initMocks(this);

		interceptor = new Authz(authorizator, authInfo, result);
		Mockito.when(authorizator.isAllowed(admin, resourceMethod)).thenReturn(
				true);
		Mockito.when(authorizator.isAllowed(user, resourceMethod)).thenReturn(
				false);
		allRoles = new HashSet<Role>(Arrays.asList(admin, user));
		noRoles = new HashSet<Role>();
	}

	@Test
	public void shouldNotAllowAccessWithoutRoles() {
		Mockito.when(authorizable.roles()).thenReturn(noRoles);
		Mockito.when(authInfo.getAuthorizable()).thenReturn(authorizable);
		interceptor.intercept(stack, resourceMethod, null);
		Mockito.verifyZeroInteractions(stack);
		Mockito.verify(authInfo).handleAuthError(result);
	}

	@Test
	public void shoudAllowAccessWithAdminRole() {
		Mockito.when(authorizable.roles()).thenReturn(allRoles);
		Mockito.when(authInfo.getAuthorizable()).thenReturn(authorizable);
		interceptor.intercept(stack, resourceMethod, null);
		Mockito.verify(stack).next(resourceMethod, null);
		Mockito.verify(authInfo, Mockito.never()).handleAuthError(result);
	}

	@Test
	public void shouldBypassAuthzIfAnnotatedWithBypass() throws SecurityException, NoSuchMethodException {
		Mockito.when(bypassedResourceMethod.getMethod()).thenReturn(FakeResource.class.getMethod("doIt"));
		Assert.assertFalse(interceptor.accepts(bypassedResourceMethod));
		Mockito.when(resourceMethod.getMethod()).thenReturn(FakeResource.class.getMethod("dontDoIt"));
		Assert.assertTrue(interceptor.accepts(resourceMethod));
	}

	static class FakeResource {
		@AuthzBypass
		public void doIt() {

		}

		public void dontDoIt() {

		}
	}

}
