package org.jahia.modules.spamfiltering.rest;

import org.jahia.api.Constants;
import org.jahia.registries.ServicesRegistry;
import org.jahia.services.usermanager.JahiaUser;

import javax.annotation.Priority;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.security.Principal;

/**
 * JAX RS Container Request filter to only allow server administrators to use the REST API
 */
@Provider
@Priority(Priorities.AUTHENTICATION) // should be one of the first post-matching filters to get executed
public class SpamFilteringAuthorizationFilter implements ContainerRequestFilter {

    @Context
    HttpServletRequest httpServletRequest;

    public SpamFilteringAuthorizationFilter() {
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        final JahiaUser jahiaUser = getCurrentUser();
        if (jahiaUser == null || !jahiaUser.isRoot()) {
            requestContext.abortWith(Response
                    .status(Response.Status.UNAUTHORIZED)
                    .entity("User cannot access the resource.")
                    .build());
            return;
        }
        requestContext.setSecurityContext(new SecurityContext() {
            @Override
            public Principal getUserPrincipal() {
                return jahiaUser;
            }

            @Override
            public boolean isUserInRole(String role) {
                return httpServletRequest.isUserInRole(role);
            }

            @Override
            public boolean isSecure() {
                return httpServletRequest.isSecure();
            }

            @Override
            public String getAuthenticationScheme() {
                return httpServletRequest.getScheme();
            }
        });
    }

    public JahiaUser getCurrentUser() {
        JahiaUser jahiaUser = null;
        HttpSession session = httpServletRequest.getSession(false);
        if (session != null) {
            try {
                jahiaUser = (JahiaUser) session.getAttribute(Constants.SESSION_USER);
            } catch (IllegalStateException ise) {
                // ignore this error that happens if the session was invalidated
            }
        }
        if (jahiaUser != null) {
            jahiaUser =
                    ServicesRegistry.getInstance().getJahiaUserManagerService().lookupUserByKey(jahiaUser.getUserKey()).getJahiaUser();
        }
        return jahiaUser;
    }

}
