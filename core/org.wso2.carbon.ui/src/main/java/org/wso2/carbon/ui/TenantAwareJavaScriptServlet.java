/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.ui;

import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Filter that intercepts requests to CSRF JavaScript servlet and delegates to JavaScriptServlet.
 * Handles both super tenant URLs (/carbon/admin/js/csrfPrevention.js)
 * and tenant URLs (/t/{tenant}/carbon/admin/js/csrfPrevention.js).
 */
public class TenantAwareJavaScriptServlet implements Filter {

    private static final String CSRF_JS_PATH = "/carbon/admin/js/csrfPrevention.js";
    private static final Pattern TENANT_PATTERN = Pattern.compile("^(/t/[^/]+)(/carbon/.*)$");
    private HttpServlet delegateServlet;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println("[CSRFGuard] TenantAwareJavaScriptServlet.init() called");
        try {
            // Load and instantiate the CSRFGuard JavaScriptServlet
            Class<?> servletClass = Class.forName("org.owasp.csrfguard.servlet.JavaScriptServlet");
            delegateServlet = (HttpServlet) servletClass.newInstance();
            System.out.println("[CSRFGuard] JavaScriptServlet loaded successfully: " + delegateServlet);
            
            // Create a minimal ServletConfig for initialization
            ServletConfig servletConfig = new ServletConfig() {
                @Override
                public String getServletName() {
                    return "CSRFGuardJavaScriptServlet";
                }

                @Override
                public ServletContext getServletContext() {
                    return filterConfig.getServletContext();
                }

                @Override
                public String getInitParameter(String name) {
                    return null;
                }

                @Override
                public java.util.Enumeration<String> getInitParameterNames() {
                    return java.util.Collections.emptyEnumeration();
                }
            };
            
            delegateServlet.init(servletConfig);
            System.out.println("[CSRFGuard] TenantAwareJavaScriptServlet initialized successfully");
        } catch (Exception e) {
            System.err.println("[CSRFGuard] Failed to initialize: " + e.getMessage());
            e.printStackTrace();
            throw new ServletException("Failed to initialize CSRFGuard JavaScriptServlet", e);
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            
            String requestURI = httpRequest.getRequestURI();
            
            // Check if this is a request for the CSRF JavaScript servlet
            // Matches: /carbon/admin/js/csrfPrevention.js or /t/{tenant}/carbon/admin/js/csrfPrevention.js
            if (requestURI != null && requestURI.endsWith(CSRF_JS_PATH)) {
                System.out.println("[CSRFGuard] *** Intercepted JavaScript request: " + requestURI);
                
                if (delegateServlet != null) {
                    // Wrap the request to adjust paths for tenant URLs
                    HttpServletRequest wrappedRequest = wrapRequestForTenant(httpRequest);
                    System.out.println("[CSRFGuard] Wrapped - ContextPath: " + wrappedRequest.getContextPath() + 
                                     ", ServletPath: " + wrappedRequest.getServletPath());
                    delegateServlet.service(wrappedRequest, httpResponse);
                    return; // Don't continue the filter chain
                } else {
                    System.err.println("[CSRFGuard] ERROR: delegateServlet is null!");
                    httpResponse.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE,
                            "CSRFGuard JavaScriptServlet not available");
                    return;
                }
            }
        }
        
        // Not a CSRF JavaScript request, continue the filter chain
        chain.doFilter(request, response);
    }

    /**
     * Wraps the request to adjust contextPath and servletPath for tenant URLs.
     * For tenant URLs like /t/wso2.com/carbon/admin/js/csrfPrevention.js,
     * sets contextPath to /t/wso2.com and servletPath to /carbon/admin/js/csrfPrevention.js
     */
    private HttpServletRequest wrapRequestForTenant(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        Matcher matcher = TENANT_PATTERN.matcher(requestURI);
        
        if (matcher.matches()) {
            // Tenant URL detected
            final String tenantPrefix = matcher.group(1);  // e.g., /t/wso2.com
            final String pathWithoutTenant = matcher.group(2);  // e.g., /carbon/admin/js/csrfPrevention.js
            
            return new HttpServletRequestWrapper(request) {
                @Override
                public String getContextPath() {
                    return tenantPrefix;
                }
                
                @Override
                public String getServletPath() {
                    return pathWithoutTenant;
                }
            };
        }
        
        // Not a tenant URL, return original request
        return request;
    }

    @Override
    public void destroy() {
        if (delegateServlet != null) {
            delegateServlet.destroy();
        }
    }
}
