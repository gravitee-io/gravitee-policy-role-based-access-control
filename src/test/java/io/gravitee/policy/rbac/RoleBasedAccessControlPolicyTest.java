/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.rbac;

import static org.mockito.Mockito.*;

import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.rbac.configuration.RoleBasedAccessControlPolicyConfiguration;
import java.util.Arrays;
import java.util.HashSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatcher;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.env.Environment;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class RoleBasedAccessControlPolicyTest {

    @Mock
    private Request mockRequest;

    @Mock
    private Response mockResponse;

    @Mock
    private ExecutionContext mockExecutionContext;

    @Mock
    private PolicyChain mockPolicychain;

    @Mock
    private RoleBasedAccessControlPolicyConfiguration policyConfiguration;

    @Mock
    private Environment environment;

    @Before
    public void init() {
        when(mockExecutionContext.getComponent(Environment.class)).thenReturn(environment);
        when(mockExecutionContext.request()).thenReturn(mockRequest);
        when(mockExecutionContext.response()).thenReturn(mockResponse);
    }

    @Test
    public void shouldFail_noUserRole() {
        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);

        when(mockExecutionContext.getAttribute(ExecutionContext.ATTR_USER_ROLES)).thenReturn(null);
        when(
            environment.getProperty(
                eq(RoleBasedAccessControlPolicy.RBAC_USER_ROLES_ATTRIBUTE_KEY),
                eq(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE)
            )
        ).thenReturn(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(
            argThat(
                new ArgumentMatcher<PolicyResult>() {
                    @Override
                    public boolean matches(PolicyResult result) {
                        return (
                            result.statusCode() == HttpStatusCode.FORBIDDEN_403 &&
                            RoleBasedAccessControlPolicy.RBAC_NO_USER_ROLE.equals(result.key())
                        );
                    }
                }
            )
        );
    }

    @Test
    public void shouldFail_invalidUserRole() {
        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);

        when(mockExecutionContext.getAttribute(ExecutionContext.ATTR_USER_ROLES)).thenReturn(new Object());
        when(policyConfiguration.hasRoles()).thenReturn(true);
        when(
            environment.getProperty(
                eq(RoleBasedAccessControlPolicy.RBAC_USER_ROLES_ATTRIBUTE_KEY),
                eq(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE)
            )
        ).thenReturn(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(
            argThat(
                new ArgumentMatcher<PolicyResult>() {
                    @Override
                    public boolean matches(PolicyResult result) {
                        return (
                            result.statusCode() == HttpStatusCode.BAD_REQUEST_400 &&
                            RoleBasedAccessControlPolicy.RBAC_INVALID_USER_ROLES.equals(result.key())
                        );
                    }
                }
            )
        );
    }

    @Test
    public void shouldValid_mustHaveRequiredScopes() {
        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);

        when(mockExecutionContext.getAttribute(ExecutionContext.ATTR_USER_ROLES)).thenReturn(Arrays.asList("read", "write", "admin"));
        when(policyConfiguration.getRoles()).thenReturn(new HashSet<>(Arrays.asList("read", "write", "admin")));
        when(policyConfiguration.isStrict()).thenReturn(true);
        when(policyConfiguration.hasRoles()).thenReturn(true);
        when(
            environment.getProperty(
                eq(RoleBasedAccessControlPolicy.RBAC_USER_ROLES_ATTRIBUTE_KEY),
                eq(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE)
            )
        ).thenReturn(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).doNext(mockRequest, mockResponse);
    }

    @Test
    public void shouldValid_shouldHaveRequiredScopes() {
        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);

        when(mockExecutionContext.getAttribute(ExecutionContext.ATTR_USER_ROLES)).thenReturn(Arrays.asList("read", "write"));
        when(policyConfiguration.getRoles()).thenReturn(new HashSet<>(Arrays.asList("read", "write", "admin")));
        when(policyConfiguration.isStrict()).thenReturn(false);
        when(policyConfiguration.hasRoles()).thenReturn(true);
        when(
            environment.getProperty(
                eq(RoleBasedAccessControlPolicy.RBAC_USER_ROLES_ATTRIBUTE_KEY),
                eq(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE)
            )
        ).thenReturn(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).doNext(mockRequest, mockResponse);
    }

    @Test
    public void shouldFail_mustHaveRequiredScopes() {
        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);

        when(mockExecutionContext.getAttribute(ExecutionContext.ATTR_USER_ROLES)).thenReturn(Arrays.asList("read", "write"));
        when(policyConfiguration.getRoles()).thenReturn(new HashSet<>(Arrays.asList("read", "write", "admin")));
        when(policyConfiguration.isStrict()).thenReturn(true);
        when(policyConfiguration.hasRoles()).thenReturn(true);
        when(
            environment.getProperty(
                eq(RoleBasedAccessControlPolicy.RBAC_USER_ROLES_ATTRIBUTE_KEY),
                eq(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE)
            )
        ).thenReturn(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(
            argThat(
                new ArgumentMatcher<PolicyResult>() {
                    @Override
                    public boolean matches(PolicyResult result) {
                        return (
                            result.statusCode() == HttpStatusCode.FORBIDDEN_403 &&
                            RoleBasedAccessControlPolicy.RBAC_FORBIDDEN.equals(result.key())
                        );
                    }
                }
            )
        );
    }

    @Test
    public void shouldFail_mustHaveRequiredScopes2() {
        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);

        when(mockExecutionContext.getAttribute(ExecutionContext.ATTR_USER_ROLES)).thenReturn(Arrays.asList("read", "write", "admin"));
        when(policyConfiguration.getRoles()).thenReturn(new HashSet<>(Arrays.asList("read", "write")));
        when(policyConfiguration.isStrict()).thenReturn(true);
        when(policyConfiguration.hasRoles()).thenReturn(true);
        when(
            environment.getProperty(
                eq(RoleBasedAccessControlPolicy.RBAC_USER_ROLES_ATTRIBUTE_KEY),
                eq(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE)
            )
        ).thenReturn(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).doNext(mockRequest, mockResponse);
    }

    @Test
    public void shouldFail_shouldHaveRequiredScopes() {
        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);

        when(mockExecutionContext.getAttribute(ExecutionContext.ATTR_USER_ROLES)).thenReturn(Arrays.asList("my-role"));
        when(policyConfiguration.getRoles()).thenReturn(new HashSet<>(Arrays.asList("read", "write", "admin")));
        when(policyConfiguration.isStrict()).thenReturn(false);
        when(policyConfiguration.hasRoles()).thenReturn(true);
        when(
            environment.getProperty(
                eq(RoleBasedAccessControlPolicy.RBAC_USER_ROLES_ATTRIBUTE_KEY),
                eq(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE)
            )
        ).thenReturn(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(
            argThat(
                new ArgumentMatcher<PolicyResult>() {
                    @Override
                    public boolean matches(PolicyResult result) {
                        return (
                            result.statusCode() == HttpStatusCode.FORBIDDEN_403 &&
                            RoleBasedAccessControlPolicy.RBAC_FORBIDDEN.equals(result.key())
                        );
                    }
                }
            )
        );
    }

    private static final String GATEWAY_CONTEXT_ATTRIBUTE_ROLES = "gateway.roles";

    @Test
    public void testOnRequestHasRole_customRoleAttribute() throws Exception {
        when(policyConfiguration.getRoles()).thenReturn(new HashSet<>(Arrays.asList("testrole", "testrole2")));
        when(mockExecutionContext.getAttribute(GATEWAY_CONTEXT_ATTRIBUTE_ROLES)).thenReturn("[\"testrole\", \"testrole2\"]");
        when(
            environment.getProperty(
                eq(RoleBasedAccessControlPolicy.RBAC_USER_ROLES_ATTRIBUTE_KEY),
                eq(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE)
            )
        ).thenReturn(GATEWAY_CONTEXT_ATTRIBUTE_ROLES);
        when(policyConfiguration.hasRoles()).thenReturn(true);

        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);
        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).doNext(mockRequest, mockResponse);
    }

    @Test
    public void testOnRequestHasRole_stringRole_customRoleAttribute() throws Exception {
        when(policyConfiguration.getRoles()).thenReturn(new HashSet<>(Arrays.asList("testrole", "testrole2")));
        when(mockExecutionContext.getAttribute(GATEWAY_CONTEXT_ATTRIBUTE_ROLES)).thenReturn("testrole testrole2");
        when(
            environment.getProperty(
                eq(RoleBasedAccessControlPolicy.RBAC_USER_ROLES_ATTRIBUTE_KEY),
                eq(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE)
            )
        ).thenReturn(GATEWAY_CONTEXT_ATTRIBUTE_ROLES);
        when(policyConfiguration.hasRoles()).thenReturn(true);

        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);
        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).doNext(mockRequest, mockResponse);
    }

    @Test
    public void testOnRequestHasRole_stringRoleWithSpaces_customRoleAttribute() throws Exception {
        when(policyConfiguration.getRoles()).thenReturn(new HashSet<>(Arrays.asList("testrole", "testrole2")));
        when(mockExecutionContext.getAttribute(GATEWAY_CONTEXT_ATTRIBUTE_ROLES)).thenReturn("testrole,  testrole2");
        when(
            environment.getProperty(
                eq(RoleBasedAccessControlPolicy.RBAC_USER_ROLES_ATTRIBUTE_KEY),
                eq(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE)
            )
        ).thenReturn(GATEWAY_CONTEXT_ATTRIBUTE_ROLES);
        when(policyConfiguration.hasRoles()).thenReturn(true);

        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);
        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).doNext(mockRequest, mockResponse);
    }

    @Test
    public void testOnRequestNoRole_customRoleAttribute() throws Exception {
        when(mockExecutionContext.getAttribute(GATEWAY_CONTEXT_ATTRIBUTE_ROLES)).thenReturn(null);
        when(environment.getProperty(eq(RoleBasedAccessControlPolicy.RBAC_USER_ROLES_ATTRIBUTE_KEY), anyString())).thenReturn(
            GATEWAY_CONTEXT_ATTRIBUTE_ROLES
        );

        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);
        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(any(PolicyResult.class));
    }

    @Test
    public void testOnRequestEmptyRole_customRoleAttribute() throws Exception {
        when(mockExecutionContext.getAttribute(GATEWAY_CONTEXT_ATTRIBUTE_ROLES)).thenReturn("[]");
        when(
            environment.getProperty(
                eq(RoleBasedAccessControlPolicy.RBAC_USER_ROLES_ATTRIBUTE_KEY),
                eq(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE)
            )
        ).thenReturn(GATEWAY_CONTEXT_ATTRIBUTE_ROLES);
        when(policyConfiguration.hasRoles()).thenReturn(true);

        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);
        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(any(PolicyResult.class));
    }

    @Test
    public void testOnRequestHasNoMatchRole_customRoleAttribute() throws Exception {
        when(policyConfiguration.getRoles()).thenReturn(new HashSet<>(Arrays.asList("testrole", "testrole2")));
        when(mockExecutionContext.getAttribute(GATEWAY_CONTEXT_ATTRIBUTE_ROLES)).thenReturn("[\"testrole1\", \"testrole3\"]");
        when(
            environment.getProperty(
                eq(RoleBasedAccessControlPolicy.RBAC_USER_ROLES_ATTRIBUTE_KEY),
                eq(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE)
            )
        ).thenReturn(GATEWAY_CONTEXT_ATTRIBUTE_ROLES);
        when(policyConfiguration.hasRoles()).thenReturn(true);

        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);
        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(any(PolicyResult.class));
    }

    @Test
    public void testOnRequestHasMatchRole_customRoleAttribute() throws Exception {
        when(policyConfiguration.getRoles()).thenReturn(new HashSet<>(Arrays.asList("testrole", "testrole2")));
        when(mockExecutionContext.getAttribute(GATEWAY_CONTEXT_ATTRIBUTE_ROLES)).thenReturn("[\"testrole\", \"testrole3\"]");
        when(
            environment.getProperty(
                eq(RoleBasedAccessControlPolicy.RBAC_USER_ROLES_ATTRIBUTE_KEY),
                eq(RoleBasedAccessControlPolicy.DEFAULT_RBAC_USER_ROLES_ATTRIBUTE)
            )
        ).thenReturn(GATEWAY_CONTEXT_ATTRIBUTE_ROLES);
        when(policyConfiguration.hasRoles()).thenReturn(true);

        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);
        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).doNext(mockRequest, mockResponse);
    }
}
