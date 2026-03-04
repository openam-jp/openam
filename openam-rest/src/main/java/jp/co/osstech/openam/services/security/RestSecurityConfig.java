/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 OSSTech Corporation
 */
package jp.co.osstech.openam.services.security;

import java.util.Map;
import java.util.Set;

import com.sun.identity.common.CaseInsensitiveHashSet;
import org.forgerock.openam.sm.config.ConfigAttribute;
import org.forgerock.openam.sm.config.ConfigSource;
import org.forgerock.openam.sm.config.ConsoleConfigBuilder;

/**
 * REST security configuration.
 */
public final class RestSecurityConfig {

    private final Set<String> selfWriteUserAttributes;

    public RestSecurityConfig(RestSecurityConfigBuilder builder) {
        selfWriteUserAttributes = builder.selfWriteUserAttributes;
    }

    /**
     * Gets the set of user attributes that users can write to themselves.
     *
     * @return self-writeable user attributes
     */
    public Set<String> getSelfWriteUserAttributes() {
        return selfWriteUserAttributes;
    }

    @ConfigSource("RestSecurity")
    public static final class RestSecurityConfigBuilder implements ConsoleConfigBuilder<RestSecurityConfig> {

        private final Set<String> selfWriteUserAttributes;

        public RestSecurityConfigBuilder() {
            selfWriteUserAttributes = new CaseInsensitiveHashSet<>();
        }

        @ConfigAttribute(value = "selfWriteUserAttributes", required = false)
        public void setSelfWriteUserAttributes(Set<String> selfWriteUserAttributes) {
            this.selfWriteUserAttributes.addAll(selfWriteUserAttributes);
        }

        @Override
        public RestSecurityConfig build(Map<String, Set<String>> attributes) {
            return new RestSecurityConfig(this);
        }
    }
}
