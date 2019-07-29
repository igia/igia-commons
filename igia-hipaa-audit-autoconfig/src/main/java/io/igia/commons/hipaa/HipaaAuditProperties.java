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

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Properties specific to igia hipaa auditing
 * <p>
 * Properties are configured in the application.yml file.
 */
@ConfigurationProperties(prefix = "igia.hipaa.audit", ignoreUnknownFields = false)
public class HipaaAuditProperties {

        /**
         * Holds the Java regex patterns of incoming request URIs that are to
         * be HIPAA audited.
         */
        private List<String> hipaaWhitelistUriPatterns = new ArrayList<>();

        /**
         * Holds the Java regex patterns of incoming request URIs that are not
         * to be HIPAA audited. Blacklisted patterns are given higher precedence
         * over whitelisted patterns.
         */
        private List<String> hipaaBlacklistUriPatterns = new ArrayList<>();
        
        /**
         * Holds the Java regex patterns of incoming request URIs for which outgoing response is to
         * be HIPAA audited.
         */
        private List<String> hipaaResponseWhitelistUriPatterns = new ArrayList<>();

        /**
         * Holds the Java regex patterns of incoming request URIs for which outgoing responses are not
         * to be HIPAA audited. Blacklisted patterns are given higher precedence
         * over whitelisted patterns.
         */
        private List<String> hipaaResponseBlacklistUriPatterns = new ArrayList<>();

		public HipaaAuditProperties() {
            hipaaWhitelistUriPatterns.add(".*/api/.*");
        }

        public List<String> getHipaaWhitelistUriPatterns() {
            return this.hipaaWhitelistUriPatterns;
        }

        public List<String> getHipaaBlacklistUriPatterns() {
            return this.hipaaBlacklistUriPatterns;
        }
        
        public List<String> getHipaaResponseWhitelistUriPatterns() {
			return hipaaResponseWhitelistUriPatterns;
		}

		public List<String> getHipaaResponseBlacklistUriPatterns() {
			return hipaaResponseBlacklistUriPatterns;
		}
}
