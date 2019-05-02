/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.rbac;

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.rbac.configuration.RoleBasedAccessControlPolicyConfiguration;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatcher;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.HashSet;

import static org.mockito.Mockito.*;

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

    @Test
    public void shouldFail_noUserRole() {
        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);

        when(mockExecutionContext.getAttribute(ExecutionContext.ATTR_USER_ROLES)).thenReturn(null);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(argThat(new ArgumentMatcher<PolicyResult>() {
            @Override
            public boolean matches(PolicyResult result) {
                return
                        result.statusCode() == HttpStatusCode.FORBIDDEN_403
                        && RoleBasedAccessControlPolicy.RBAC_NO_USER_ROLE.equals(result.key());
            }
        }));
    }

    @Test
    public void shouldFail_invalidUserRole() {
        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);

        when(mockExecutionContext.getAttribute(ExecutionContext.ATTR_USER_ROLES)).thenReturn(new Object());
        when(policyConfiguration.hasRoles()).thenReturn(true);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(argThat(new ArgumentMatcher<PolicyResult>() {
            @Override
            public boolean matches(PolicyResult result) {
                return
                        result.statusCode() == HttpStatusCode.BAD_REQUEST_400
                                && RoleBasedAccessControlPolicy.RBAC_INVALID_USER_ROLES.equals(result.key());
            }
        }));
    }

    @Test
    public void shouldValid_mustHaveRequiredScopes() {
        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);

        when(mockExecutionContext.getAttribute(ExecutionContext.ATTR_USER_ROLES)).thenReturn(Arrays.asList("read", "write", "admin"));
        when(policyConfiguration.getRoles()).thenReturn(new HashSet<>(Arrays.asList("read", "write", "admin")));
        when(policyConfiguration.isStrict()).thenReturn(true);
        when(policyConfiguration.hasRoles()).thenReturn(true);

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

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(argThat(new ArgumentMatcher<PolicyResult>() {
            @Override
            public boolean matches(PolicyResult result) {
                return
                        result.statusCode() == HttpStatusCode.FORBIDDEN_403
                                && RoleBasedAccessControlPolicy.RBAC_FORBIDDEN.equals(result.key());
            }
        }));
    }

    @Test
    public void shouldFail_shouldHaveRequiredScopes() {
        RoleBasedAccessControlPolicy policy = new RoleBasedAccessControlPolicy(policyConfiguration);

        when(mockExecutionContext.getAttribute(ExecutionContext.ATTR_USER_ROLES)).thenReturn(Arrays.asList("my-role"));
        when(policyConfiguration.getRoles()).thenReturn(new HashSet<>(Arrays.asList("read", "write", "admin")));
        when(policyConfiguration.isStrict()).thenReturn(false);
        when(policyConfiguration.hasRoles()).thenReturn(true);

        policy.onRequest(mockRequest, mockResponse, mockExecutionContext, mockPolicychain);

        verify(mockPolicychain).failWith(argThat(new ArgumentMatcher<PolicyResult>() {
            @Override
            public boolean matches(PolicyResult result) {
                return
                        result.statusCode() == HttpStatusCode.FORBIDDEN_403
                                && RoleBasedAccessControlPolicy.RBAC_FORBIDDEN.equals(result.key());
            }
        }));
    }
}
