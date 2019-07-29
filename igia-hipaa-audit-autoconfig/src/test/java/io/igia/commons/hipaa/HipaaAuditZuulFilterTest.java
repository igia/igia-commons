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

import com.netflix.zuul.context.RequestContext;

import io.igia.commons.hipaa.HipaaAuditProperties;
import io.igia.commons.hipaa.HipaaAuditZuulFilter;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;


public class HipaaAuditZuulFilterTest {

    @Mock
    private ApplicationEventPublisher publisher;

    @Mock
    private HipaaAuditProperties applicationProperties;

    private HipaaAuditZuulFilter filter;

    @Before()
    public void setup() {
        MockitoAnnotations.initMocks(this);

        String[] blackListUris = {"^/uaaserver.*", ".*/gateway/.*", ".*/api/healthcheck/alive\\.json$", ".*/api/profile-info$"};
        String[] whitelistUris = {".*/api/.*"};

        HipaaAuditProperties auditConfiguration = new HipaaAuditProperties();
        auditConfiguration.getHipaaBlacklistUriPatterns().addAll(Arrays.asList(blackListUris));
        auditConfiguration.getHipaaWhitelistUriPatterns().addAll(Arrays.asList(whitelistUris));
        applicationProperties = auditConfiguration;

        filter = new HipaaAuditZuulFilter(publisher, applicationProperties);
    }

    @Test
    public void shouldFilterBlacklistedUri_1() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/cardiocompassuiapi/api/healthcheck/alive.json");
        RequestContext.getCurrentContext().setRequest(request);
        assertThat(filter.shouldFilter()).isFalse();
    }

    @Test
    public void shouldFilterBlacklistedUri_2() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/cardiocompassuiapi/api/profile-info");
        RequestContext.getCurrentContext().setRequest(request);
        assertThat(filter.shouldFilter()).isFalse();
    }

    @Test
    public void shouldFilterBlacklistedUri_3() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/uaaserver/api/account");
        RequestContext.getCurrentContext().setRequest(request);
        assertThat(filter.shouldFilter()).isFalse();
    }

    @Test
    public void shouldFilterBlacklistedUri_4() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/gateway/routes/");
        RequestContext.getCurrentContext().setRequest(request);
        assertThat(filter.shouldFilter()).isFalse();
    }

    @Test
    public void shouldFilterWhitelistedUri_1() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/cardiocompassuiapi/api/all.json");
        RequestContext.getCurrentContext().setRequest(request);
        assertThat(filter.shouldFilter()).isTrue();
    }

    @Test
    public void shouldFilterWhitelistedUri_2() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/cardiocompassuiapi/api/patient/add.json");
        RequestContext.getCurrentContext().setRequest(request);
        assertThat(filter.shouldFilter()).isTrue();
    }

    @Test
    public void shouldFilterUnknownUri() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "v1/patient.json");
        RequestContext.getCurrentContext().setRequest(request);
        assertThat(filter.shouldFilter()).isFalse();
    }
    
    @Test
    public void shouldFilterOpitons() {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "v1/patient.json");
        RequestContext.getCurrentContext().setRequest(request);
        assertThat(filter.shouldFilter()).isFalse();
    }
}
