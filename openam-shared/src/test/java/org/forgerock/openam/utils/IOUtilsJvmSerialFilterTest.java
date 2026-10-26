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
 * Copyright 2026 3A Systems, LLC.
 * Portions copyright 2026 OSSTech Corporation
 */
package org.forgerock.openam.utils;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.Collections;

import jp.co.osstech.openam.utils.ObjectInputFilterSupport;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Pins that {@link IOUtils#deserialise(byte[], boolean)} keeps a JVM-wide {@code jdk.serialFilter} in force.
 * The JVM filter can be set only once per JVM, so this class runs in its own surefire execution with
 * {@code -Djdk.serialFilter=!java.util.Collections$SingletonList} and is excluded from the default one.
 */
public class IOUtilsJvmSerialFilterTest {

    @Test
    public void shouldHonourJvmWideSerialFilter() throws Exception {
        // The filter API is sun.misc.ObjectInputFilter on Java 8 and java.io.ObjectInputFilter from Java 9, so the
        // system property is checked instead of ObjectInputFilter.Config.getSerialFilter().
        assertThat(System.getProperty("jdk.serialFilter"))
                .as("jdk.serialFilter must be set by the jvm-serial-filter surefire execution")
                .isNotNull();
        assertThat(ObjectInputFilterSupport.isAvailable())
                .as("the JVM must provide a JEP 290 filter API (Java 8u121 or later)")
                .isTrue();
        // The class is whitelisted, so only the JVM-wide filter can reject it.
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(Collections.singletonList("a"));
        }

        try {
            IOUtils.deserialise(bytes.toByteArray(), false);
            Assert.fail("Expected the JVM-wide jdk.serialFilter to reject java.util.Collections$SingletonList");
        } catch (IOException expected) {
            // Rejected by the JVM-wide filter, as required.
        }
    }
}
