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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import io.igia.commons.hipaa.HipaaAuditProperties;
import io.igia.commons.hipaa.HipaaAuditZuulFilter;

@Configuration
@Import(HipaaAuditProperties.class)
public class HipaaAuditConfig {
	
	private final Logger log = LoggerFactory.getLogger(HipaaAuditConfig.class);
	
	@Bean
	public HipaaAuditZuulFilter hipaaAuditZuulFilter(ApplicationEventPublisher publisher, HipaaAuditProperties
	 applicationProperties) {
		log.info("Configuring Hippa Audit Zuul Filter");
		return new HipaaAuditZuulFilter(publisher, applicationProperties);
	}
	
	@Bean
	public HipaaResponseAuditZuulFilter hipaaResponseAuditZuulFilter(ApplicationEventPublisher publisher, HipaaAuditProperties
	 applicationProperties) {
		log.info("Configuring Hippa Response Audit Zuul Filter");
		return new HipaaResponseAuditZuulFilter(publisher, applicationProperties);
	}
}

