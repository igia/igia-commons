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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.cloud.netflix.zuul.util.ZuulRuntimeException;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

/**
 * Class which extends ZuulFilter and logs an audit event for API responses.
 * Response body is logged.
 * Should be used for queries in which multiple patient's data might be returned.
 * Filter order is right before SendResponseFilter.
 */
public class HipaaResponseAuditZuulFilter extends ZuulFilter {
	public static final String AUDIT_APPLICATION_EVENT_TYPE = "HIPAA_AUDIT";

	private final Logger log = LoggerFactory.getLogger(HipaaResponseAuditZuulFilter.class);
	
	private HipaaAuditProperties applicationProperties;

	private ApplicationEventPublisher publisher;
	
    @Autowired
    public HipaaResponseAuditZuulFilter(ApplicationEventPublisher publisher, HipaaAuditProperties applicationProperties) {
        this.publisher = publisher;
        this.applicationProperties = applicationProperties;
    }

	@Override
	public String filterType() {
		return FilterConstants.POST_TYPE;
	}

	@Override
	public int filterOrder() {
		// TODO right before SendResponseFilter, check if there is a better place to avoid unzip response
		return FilterConstants.SEND_RESPONSE_FILTER_ORDER - 1;
	}

	/**
	 * Determine whether the response should be audited.
	 */
	@Override
	public boolean shouldFilter(){
        String requestMethod = RequestContext.getCurrentContext().getRequest().getMethod();
        if (!requestMethod.equals(HttpMethod.GET.name()) &&
        		!requestMethod.equals(HttpMethod.POST.name())) {
            return false;
        }
               
        String requestUri = (RequestContext.getCurrentContext().getRequest().getQueryString() != null) ? 
        		String.join("", RequestContext.getCurrentContext().getRequest().getRequestURI(), "?", RequestContext.getCurrentContext().getRequest().getQueryString()) 
        		: RequestContext.getCurrentContext().getRequest().getRequestURI() ;
        return (!isRequestUriInBlacklistPatterns(requestUri)
            && isRequestUriInWhitelistPatterns(requestUri));
	}
	
    private boolean isRequestUriInBlacklistPatterns(String requestUri) {
        Collection<String> patterns = this.applicationProperties.getHipaaResponseBlacklistUriPatterns();
        boolean isAvailable = patterns.stream().anyMatch(s->requestUri.matches(s));
    	return isAvailable;
    	
    }

    private boolean isRequestUriInWhitelistPatterns(String requestUri) {
    	Collection<String> patterns = this.applicationProperties.getHipaaResponseWhitelistUriPatterns();
        boolean isAvailable = patterns.stream().anyMatch(s->requestUri.matches(s));
    	return isAvailable;
    }

	@Override
	public Object run() {
		String principal = SecurityContextHolder.getContext().getAuthentication().getName();
		Map<String, Object> data = new HashMap<String, Object>();

		RequestContext ctx = RequestContext.getCurrentContext();

		// TODO more checking
		try (final InputStream responseDataStream = ctx.getResponseDataStream()) {
			final byte[] ba = IOUtils.toByteArray(responseDataStream);
			InputStream is = new ByteArrayInputStream(ba);
			if (ctx.getResponseGZipped()) {
				 is = new GZIPInputStream(is);
			}
			
			String responseBody = IOUtils.toString(is, ctx.getResponse().getCharacterEncoding());
			data.put("responseBody", responseBody);
			data.put("remoteAddress", ctx.getRequest().getRemoteAddr());
			data.put("message", String.join("", "API ", ctx.getRequest().getRequestURI(), " accessed"));
			
			ctx.setResponseDataStream(new ByteArrayInputStream(ba));
		} catch (IOException e) {
			log.error("Error reading response body", e);
			throw new ZuulRuntimeException(
					new ZuulException(e, HttpStatus.INTERNAL_SERVER_ERROR.value(), e.getMessage()));			
		}

		AuditApplicationEvent event = new AuditApplicationEvent(principal, AUDIT_APPLICATION_EVENT_TYPE, data);	
		publisher.publishEvent(event);

		return null;
	}
}
