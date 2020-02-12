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
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.rbac.configuration.RoleBasedAccessControlPolicyConfiguration;

import java.util.Collection;
import java.util.List;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class RoleBasedAccessControlPolicy {

    /**
     * The associated configuration to this Role-Based-Access-Control Policy
     */
    private RoleBasedAccessControlPolicyConfiguration configuration;

    static final String RBAC_NO_USER_ROLE = "RBAC_NO_USER_ROLE";

    static final String RBAC_INVALID_USER_ROLES = "RBAC_INVALID_USER_ROLES";

    static final String RBAC_FORBIDDEN = "RBAC_FORBIDDEN";

    /**
     * Create a new Role-Based-Access-Control Policy instance based on its associated configuration
     *
     * @param configuration the associated configuration to the new Role-Based-Access-Control Policy instance
     */
    public RoleBasedAccessControlPolicy(RoleBasedAccessControlPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext context, PolicyChain policyChain) {
        Object userRolesAttribute = context.getAttribute(ExecutionContext.ATTR_USER_ROLES);

        if (userRolesAttribute == null) {
            // No role for the current HTTP request
            policyChain.failWith(
                    PolicyResult.failure(
                            RBAC_NO_USER_ROLE,
                            HttpStatusCode.FORBIDDEN_403,
                            "There is no user role associated to the current request."));
        } else if (configuration.hasRoles()) {
            if (userRolesAttribute instanceof List) {
                if (hasRequiredRoles((List) userRolesAttribute)) {
                    policyChain.doNext(request, response);
                } else {
                    // The user roles do not contain one of the expected role
                    policyChain.failWith(
                            PolicyResult.failure(
                                    RBAC_FORBIDDEN,
                                    HttpStatusCode.FORBIDDEN_403,
                                    "User is not allowed to access this route."));
                }
            } else {
                // The user roles structure is not the one expected
                policyChain.failWith(
                        PolicyResult.failure(
                                RBAC_INVALID_USER_ROLES,
                                HttpStatusCode.BAD_REQUEST_400,
                                "User roles are not valid."));
            }
        } else {
            // No required role defined, continue request processing
            policyChain.doNext(request, response);
        }
    }

    private boolean hasRequiredRoles(final Collection<String> userRoles) {
        if (userRoles == null || userRoles.isEmpty()) {
            return false;
        }

        if (configuration.isStrict()) {
            return userRoles.containsAll(configuration.getRoles());
        } else {
            return userRoles.stream().anyMatch(configuration.getRoles()::contains);
        }
    }
}
