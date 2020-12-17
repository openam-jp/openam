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
 * Copyright 2014 ForgeRock AS.
 * Portions copyright 2019 Open Source Solution Technology Corporation
 */
package org.forgerock.openam.cts.impl.query.reaper;

import org.forgerock.openam.cts.exceptions.CoreTokenException;
import org.forgerock.openam.cts.reaper.CTSReaper;

import java.io.Closeable;
import java.util.Collection;

/**
 * Defines the behaviour of the CTS Reaper paged question which will locate all expired Tokens
 * in the persistence layer.
 *
 * @see CTSReaper
 */
public interface ReaperQuery extends Closeable {
    /**
     * Repeated calls will return further results from query.
     *
     * @return Whilst there are further results, non null, non empty collection of the Token ID
     * of each Token to be purged by the CTS Reaper. Once there are no more results then null.
     *
     * @throws CoreTokenException If there was any unexpected error during processing.
     */
    Collection<String> nextPage() throws CoreTokenException;
}
