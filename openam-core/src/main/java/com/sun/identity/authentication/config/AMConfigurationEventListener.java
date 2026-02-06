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

package com.sun.identity.authentication.config;

public interface AMConfigurationEventListener {

    /**
     * Processes listener event, this method will remove configuration from
     * the configuration cache, also remove the listener from the listened
     * object, such as <code>AMUser</code>, <code>AMRole</code>, or SM Service.
     *
     * @param name Configuration name.
     */
    public void processListenerEvent(String name);
}
