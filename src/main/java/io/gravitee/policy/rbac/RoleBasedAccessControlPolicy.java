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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.rbac.configuration.RoleBasedAccessControlPolicyConfiguration;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class RoleBasedAccessControlPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(RoleBasedAccessControlPolicy.class);

    /**
     * The associated configuration to this Role-Based-Access-Control Policy
     */
    private RoleBasedAccessControlPolicyConfiguration configuration;

    static final String RBAC_NO_USER_ROLE = "RBAC_NO_USER_ROLE";

    static final String RBAC_INVALID_USER_ROLES = "RBAC_INVALID_USER_ROLES";

    static final String RBAC_FORBIDDEN = "RBAC_FORBIDDEN";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private String userRolesAttribute;

    static final String RBAC_USER_ROLES_ATTRIBUTE_KEY = "policy.rbac.attributes.roles";
    static final String DEFAULT_RBAC_USER_ROLES_ATTRIBUTE = ExecutionContext.ATTR_USER_ROLES;

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
        Object userRolesAttribute = context.getAttribute(getRolesAttribute(context));

        if (userRolesAttribute == null) {
            // No role for the current HTTP request
            policyChain.failWith(
                PolicyResult.failure(
                    RBAC_NO_USER_ROLE,
                    HttpStatusCode.FORBIDDEN_403,
                    "There is no user role associated to the current request."
                )
            );
        } else if (configuration.hasRoles()) {
            if (userRolesAttribute instanceof List) {
                processRoles((List) userRolesAttribute, policyChain, context);
            } else if (userRolesAttribute instanceof String) {
                Set<String> roles = parseString((String) userRolesAttribute);
                processRoles(roles, policyChain, context);
            } else {
                // The user roles structure is not the one expected
                policyChain.failWith(
                    PolicyResult.failure(RBAC_INVALID_USER_ROLES, HttpStatusCode.BAD_REQUEST_400, "User roles are not valid.")
                );
            }
        } else {
            // No required role defined, continue request processing
            policyChain.doNext(request, response);
        }
    }

    private void processRoles(final Collection<String> userRoles, PolicyChain policyChain, ExecutionContext context) {
        if (hasRequiredRoles(userRoles)) {
            policyChain.doNext(context.request(), context.response());
        } else {
            // The user roles do not contain one of the expected role
            policyChain.failWith(
                PolicyResult.failure(RBAC_FORBIDDEN, HttpStatusCode.FORBIDDEN_403, "User is not allowed to access this route.")
            );
        }
    }

    private Set<String> parseString(String rolesStr) {
        // Two cases
        // 2_ json format
        // 1_ array of string (separated by a space)
        try {
            return MAPPER.readValue(rolesStr, Set.class);
        } catch (IOException e) {
            return Arrays.stream(rolesStr.split("\\s+|,\\s*")).collect(Collectors.toSet());
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

    private String getRolesAttribute(ExecutionContext context) {
        if (userRolesAttribute == null) {
            Environment environment = context.getComponent(Environment.class);
            userRolesAttribute = environment.getProperty(RBAC_USER_ROLES_ATTRIBUTE_KEY, DEFAULT_RBAC_USER_ROLES_ATTRIBUTE);
        }

        return userRolesAttribute;
    }
}
