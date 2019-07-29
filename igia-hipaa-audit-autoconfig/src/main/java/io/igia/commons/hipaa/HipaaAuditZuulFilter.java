/**
 * This Source Code Form is subject to the terms of the Mozilla Public License, v.
 * 2.0 with a Healthcare Disclaimer.
 * A copy of the Mozilla Public License, v. 2.0 with the Healthcare Disclaimer can
 * be found under the top level directory, named LICENSE.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 * If a copy of the Healthcare Disclaimer was not distributed with this file, You
 * can obtain one at the project website https://github.com/igia.
 *
 * Copyright (C) 2018-2019 Persistent Systems, Inc.
 */
package io.igia.commons.hipaa;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.context.SecurityContextHolder;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

public class HipaaAuditZuulFilter extends ZuulFilter {
	public static final String AUDIT_APPLICATION_EVENT_TYPE = "HIPAA_AUDIT";
	
    private final ApplicationEventPublisher publisher;

    private HipaaAuditProperties applicationProperties;

    @Autowired
    public HipaaAuditZuulFilter(ApplicationEventPublisher publisher, HipaaAuditProperties applicationProperties) {
        this.publisher = publisher;
        this.applicationProperties = applicationProperties;
    }

    @Override
    public String filterType() {
        return FilterConstants.PRE_TYPE;
    }

    @Override
    public int filterOrder() {
        return 20;
    }

    /**
     * Determine whether the requestUrl should be audited.
     */
    @Override
    public boolean shouldFilter() {
        String requestMethod = RequestContext.getCurrentContext().getRequest().getMethod();
        if (requestMethod.equals(HttpMethod.OPTIONS.name())) {
            return false;
        } 

        String requestUri = RequestContext.getCurrentContext().getRequest().getRequestURI();
         return (!isRequestUriInBlacklistPatterns(requestUri)
             && isRequestUriInWhitelistPatterns(requestUri));
    }

    private boolean isRequestUriInBlacklistPatterns(String requestUri) {
        Collection<String> patterns = this.applicationProperties.getHipaaBlacklistUriPatterns();
        boolean isAvailable = patterns.stream().anyMatch(s->requestUri.matches(s));
    	return isAvailable;
    	
    }

    private boolean isRequestUriInWhitelistPatterns(String requestUri) {
    	Collection<String> patterns = this.applicationProperties.getHipaaWhitelistUriPatterns();
        boolean isAvailable = patterns.stream().anyMatch(s->requestUri.matches(s));
    	return isAvailable;
    }

    @Override
    public Object run() {
        String principal = SecurityContextHolder.getContext().getAuthentication().getName();
        Map<String, Object> data = new HashMap<>();
        HttpServletRequest req = RequestContext.getCurrentContext().getRequest();

        data.put("remoteAddress", req.getRemoteAddr());
        data.put("httpMethod", req.getMethod());
        data.put("requestUri", req.getRequestURI());
        data.put("requestParam", convert(req.getParameterMap()));
        data.put("message", String.join("", "Attempt to access API ", req.getRequestURI()));

        AuditApplicationEvent event = new AuditApplicationEvent(principal, AUDIT_APPLICATION_EVENT_TYPE, data);
        publisher.publishEvent(event);
        return null;
    }

    private String convert(Map<String, String[]> paraMap) {
        return paraMap.entrySet()
            .stream()
            .filter(s -> !"cacheBuster".equals(s.getKey()))
            .map(s -> s.getKey() + ":" + Arrays.toString(s.getValue()))
            .collect(Collectors.joining(", "));
    }
}
