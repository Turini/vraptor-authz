package br.com.caelum.vraptor.authz;

import me.qmx.vraptor.authz.Authz;
import me.qmx.vraptor.authz.Authorizator;
import me.qmx.vraptor.authz.AuthzInfo;
import me.qmx.vraptor.authz.Role;
import me.qmx.vraptor.authz.Authorizable;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import br.com.caelum.vraptor.Result;
import me.qmx.vraptor.authz.annotation.AuthzBypass;
import br.com.caelum.vraptor.core.InterceptorStack;
import br.com.caelum.vraptor.http.route.Router;
import br.com.caelum.vraptor.resource.DefaultResourceClass;
import br.com.caelum.vraptor.resource.HttpMethod;
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

	@Mock
	private Router router;

	private Authz interceptor;
	private Set<Role> allRoles;
	private Set<Role> noRoles;

	@Mock
	private HttpServletRequest request;

	@Before
	public void setUp() throws Exception {
		MockitoAnnotations.initMocks(this);
		when(request.getRequestURI()).thenReturn("/mycontext/mytest");
		when(request.getContextPath()).thenReturn("/mycontext");
		when(router.allowedMethodsFor(any(String.class))).thenReturn(EnumSet.of(HttpMethod.GET));
		interceptor = new Authz(authorizator, authInfo, result, router, request);
		when(authorizator.isAllowed(admin, "/mytest", EnumSet.of(HttpMethod.GET))).thenReturn(true);
		when(authorizator.isAllowed(user, "/mytest", EnumSet.of(HttpMethod.GET))).thenReturn(false);
		allRoles = new HashSet<Role>(Arrays.asList(admin, user));
		noRoles = new HashSet<Role>();
	}

	@SuppressWarnings("unchecked")
	@Test
	public void shouldNotAllowAccessWithoutRoles() throws SecurityException, NoSuchMethodException {
		when(request.getMethod()).thenReturn(HttpMethod.GET.name());
		when(resourceMethod.getResource()).thenReturn(new DefaultResourceClass(FakeResource.class));
		when(resourceMethod.getMethod()).thenReturn(FakeResource.class.getMethod("doIt"));
		when(router.urlFor(any(Class.class), any(Method.class))).thenReturn("/");
		when(authorizable.roles()).thenReturn(noRoles);
		when(authInfo.getAuthorizable()).thenReturn(authorizable);
		interceptor.intercept(stack, resourceMethod, null);
		verifyZeroInteractions(stack);
		verify(authInfo).handleAuthError(result);
	}

	@Test
	public void shoudAllowAccessWithAdminRole() throws SecurityException, NoSuchMethodException {
		when(request.getMethod()).thenReturn(HttpMethod.GET.name());
		when(resourceMethod.getResource()).thenReturn(new DefaultResourceClass(FakeResource.class));
		when(resourceMethod.getMethod()).thenReturn(FakeResource.class.getMethod("doIt"));
		when(authorizable.roles()).thenReturn(allRoles);
		when(authInfo.getAuthorizable()).thenReturn(authorizable);
		interceptor.intercept(stack, resourceMethod, null);
		verify(stack).next(resourceMethod, null);
		verify(authInfo, never()).handleAuthError(result);
	}

	@Test
	public void shouldDenyAccessWithWrongMethod() throws SecurityException, NoSuchMethodException {
		when(request.getMethod()).thenReturn(HttpMethod.POST.name());
		when(resourceMethod.getResource()).thenReturn(new DefaultResourceClass(FakeResource.class));
		when(resourceMethod.getMethod()).thenReturn(FakeResource.class.getMethod("doIt"));
		when(authorizable.roles()).thenReturn(allRoles);
		when(authInfo.getAuthorizable()).thenReturn(authorizable);
		interceptor.intercept(stack, resourceMethod, null);
		verifyZeroInteractions(stack);
		verify(authInfo).handleAuthError(result);
	}

	@Test
	public void shouldBypassAuthzIfAnnotatedWithBypass() throws SecurityException, NoSuchMethodException {
		when(bypassedResourceMethod.getMethod()).thenReturn(FakeResource.class.getMethod("doIt"));
		when(bypassedResourceMethod.getResource()).thenReturn(new DefaultResourceClass(FakeResource.class));
		Assert.assertFalse(interceptor.accepts(bypassedResourceMethod));
		when(resourceMethod.getResource()).thenReturn(new DefaultResourceClass(FakeResource.class));
		when(resourceMethod.getMethod()).thenReturn(FakeResource.class.getMethod("dontDoIt"));
		Assert.assertTrue(interceptor.accepts(resourceMethod));
	}

	static class FakeResource {
		@AuthzBypass
		public void doIt() {

		}

		public void dontDoIt() {

		}
	}

	@Test
	public void shouldBypassAuthzIfTypeIsAnnotatedWithBypass() throws SecurityException, NoSuchMethodException {
		when(bypassedResourceMethod.getMethod()).thenReturn(CreativeCommonsResource.class.getMethod("modifyMe"));
		when(bypassedResourceMethod.getResource()).thenReturn(new DefaultResourceClass(CreativeCommonsResource.class));
		Assert.assertFalse(interceptor.accepts(bypassedResourceMethod));
	}

	@AuthzBypass
	static class CreativeCommonsResource {
		public void modifyMe() {

		}
	}

	@Test
	public void shouldBypassAuthzIfAnnotationIsInTypeHierarchy() throws SecurityException, NoSuchMethodException {
		when(bypassedResourceMethod.getMethod()).thenReturn(MyPhoto.class.getMethod("newWork"));
		when(bypassedResourceMethod.getResource()).thenReturn(new DefaultResourceClass(MyPhoto.class));
		Assert.assertFalse(interceptor.accepts(bypassedResourceMethod));
	}

	static class MyPhoto extends CreativeCommonsResource {
		public void newWork() {
		}
	}

}
