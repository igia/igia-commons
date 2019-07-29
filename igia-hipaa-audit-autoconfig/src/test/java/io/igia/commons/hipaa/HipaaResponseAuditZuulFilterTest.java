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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.cloud.netflix.zuul.metrics.EmptyCounterFactory;
import org.springframework.cloud.netflix.zuul.util.ZuulRuntimeException;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import com.netflix.zuul.monitoring.CounterFactory;

@RunWith(SpringJUnit4ClassRunner.class)
public class HipaaResponseAuditZuulFilterTest {
	
	@InjectMocks
	private HipaaResponseAuditZuulFilter filter;
	
	@MockBean
	private ApplicationEventPublisher publisher;
	
	@MockBean
	private HipaaAuditProperties applicationProperties;
	
	private AuditApplicationEvent event;
	
	@Before
    public void init(){
        MockitoAnnotations.initMocks(this);
        
        String[] blackListUris = {".*/gateway/.*", ".*/api/healthcheck/alive\\.json$", ".*/api/profile-info$"};
        String[] whitelistUris = {".*/api/.*", ".*/Patient\\?.*"};
        
    	when(applicationProperties.getHipaaResponseBlacklistUriPatterns()).thenReturn(Arrays.asList(blackListUris));
    	when(applicationProperties.getHipaaResponseWhitelistUriPatterns()).thenReturn(Arrays.asList(whitelistUris));
    	
    	CounterFactory.initialize(new EmptyCounterFactory());
    }
	
	@Test
	public void testShouldFilterWhitelistUri() throws UnsupportedEncodingException {
		String requestUri = "/api/test";
    	
    	// setup request context
		MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), requestUri);		
		createRequestContext(request, "content");
				
		assertThat(filter.shouldFilter()).as("shouldFilter white list URI").isTrue();
	}
	
	@Test
	public void testShouldNotFilterBlacklistUri() throws UnsupportedEncodingException {
		String requestUri = "/api/profile-info";		
    	
    	// setup request context
    	MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), requestUri);		
		createRequestContext(request, "content");
				
		assertThat(filter.shouldFilter()).as("should not filter black list URI").isFalse();
	}
	
	@Test
	public void testShouldFilterQueryUri() throws UnsupportedEncodingException {
		String requestUri = "/Patient?identifier=12345";		
    	
    	// setup request context
    	MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), requestUri);		
		createRequestContext(request, "content");
				
		assertThat(filter.shouldFilter()).as("should filter query URI").isTrue();
	}
	
	@Test
	public void testShouldNotFilterOtherUri() throws UnsupportedEncodingException {
		String requestUri = "/other";		
    	
    	// setup request context
    	MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), requestUri);		
		createRequestContext(request, "content");
				
		assertThat(filter.shouldFilter()).as("should not filter other URI").isFalse();
	}
	
	@Test
	public void testShouldNotFilterNonGetOrPostRequest() throws UnsupportedEncodingException {		
		String requestUri = "/api/test";		
		
    	// setup request context
    	MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.OPTIONS.name(), requestUri);		
		createRequestContext(request, "content");
				
		assertThat(filter.shouldFilter()).as("should not filter options request method").isFalse();
	}

	@Test
	public void testRunsNormally() throws ZuulException, UnsupportedEncodingException {
		String principal = "admin";
		String requestUri = "http://localhost:8080/api/test";
		String responseBody = "content";
		
		setupMocks(principal);
		
    	// setup request context
    	MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), requestUri);			
		createRequestContext(request, responseBody);		
		
		filter.run();
		assertThat(event).as("AuditApplicationEvent not null").isNotNull();
		assertThat(event.getAuditEvent()).as("AuditEvent not null").isNotNull();
		assertThat(event.getAuditEvent().getPrincipal()).as("Principal not null").isNotNull();
		assertThat(event.getAuditEvent().getPrincipal()).as("Principal equals \"admin\"").asString().isEqualTo(principal);	
		assertThat(event.getAuditEvent().getType()).as("Type equals \"HIPAA_AUDIT\"").asString().isEqualTo(HipaaResponseAuditZuulFilter.AUDIT_APPLICATION_EVENT_TYPE);	
		assertThat(event.getAuditEvent().getData().get("responseBody")).as("responseBody equals \"content\"").asString().isEqualTo(responseBody);	
	}
	
	@Test(expected = ZuulRuntimeException.class)
	public void testRunsWithException() throws ZuulException, UnsupportedEncodingException {
		String principal = "admin";
		String requestUri = "http://localhost:8080/api/test";
		String responseBody = "content";
		
		setupMocks(principal);
		
    	// setup request context
    	MockHttpServletRequest request = new MockHttpServletRequest(HttpMethod.GET.name(), requestUri);					
		RequestContext context = createRequestContext(request, responseBody);
		context.setResponseGZipped(true);
		
		filter.run();
	}
	
	private RequestContext createRequestContext(HttpServletRequest request, String responseBody) throws UnsupportedEncodingException {		
		RequestContext context = new RequestContext();
		context.setRequest(request);
		context.setResponse(new MockHttpServletResponse());
		context.setResponseDataStream(
				new ByteArrayInputStream(responseBody.getBytes(StandardCharsets.UTF_8)));
		context.setResponseGZipped(false);
		RequestContext.testSetCurrentContext(context);
		return context;
	}
	
    private void setupMocks(String principal) {
    	// setup authentication
    	Authentication authentication = Mockito.mock(Authentication.class);
    	SecurityContext securityContext = Mockito.mock(SecurityContext.class);
    	when(authentication.getName()).thenReturn(principal);
    	when(securityContext.getAuthentication()).thenReturn(authentication);
    	SecurityContextHolder.setContext(securityContext);
    	
    	// capture audit event
    	event = null;
    	Mockito.doAnswer(new Answer<Object>() {
		    @Override
		    public Object answer(InvocationOnMock invocation) throws Throwable {
		    	event = (AuditApplicationEvent) invocation.getArguments()[0];
		        return null;
		    }
		}).when(publisher).publishEvent(ArgumentMatchers.any());
    }
}
