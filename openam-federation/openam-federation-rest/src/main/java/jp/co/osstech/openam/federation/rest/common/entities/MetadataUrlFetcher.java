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
 * Portions Copyrighted 2026 OSSTech Corporation
 */
package jp.co.osstech.openam.federation.rest.common.entities;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;

import com.iplanet.am.util.SystemProperties;
import com.sun.identity.common.SsrfUrlValidator;

/**
 * Fetches the metadata behind the {@code metadataUrl} of a remote entity import request without
 * letting the URL reach the OpenAM server's internal network (GHSA-rmw3-j353-w9f7).
 *
 * <p>The rules are those of {@code com.sun.identity.workflow.WebContentFetcher}, which guards the
 * same import in the console wizards: every hop, the original URL and each redirect target alike,
 * must use {@code http} or {@code https} and must not resolve to an address that
 * {@link SsrfUrlValidator} blocks. Redirects are followed here rather than by
 * {@code HttpURLConnection}, at most {@value #MAX_REDIRECTS} of them, and a redirect may upgrade
 * {@code http} to {@code https} but never leave {@code https}.
 *
 * <p>The address check — never the scheme check — is lifted by the same property as the console
 * wizards, {@link #ALLOW_ANY_ADDRESS_PROPERTY}, so that one switch covers every metadata URL
 * import. Without it, the metadata of a partner on an internal address can still be imported by
 * passing the document itself in {@code metadata}.
 *
 * <p>The host is resolved here and resolved again when the connection is opened, so a hostile DNS
 * server can answer differently the second time (DNS rebinding), and a JVM-wide HTTP proxy
 * resolves the host itself; both limits are shared with the other SSRF guards in OpenAM.
 */
class MetadataUrlFetcher {

    /**
     * When {@code true}, a metadata URL may resolve to an internal or special-purpose address. The
     * {@code http}/{@code https} scheme allowlist still applies. Default {@code false}. Shared with
     * the console wizards.
     */
    static final String ALLOW_ANY_ADDRESS_PROPERTY =
            "org.openidentityplatform.federation.workflow.allow-any-address";

    /** How many {@code 3xx} hops are followed before the fetch is abandoned. */
    static final int MAX_REDIRECTS = 3;

    /** {@code HttpURLConnection} has no constant for {@code 307 Temporary Redirect}. */
    private static final int HTTP_TEMPORARY_REDIRECT = 307;

    /** {@code HttpURLConnection} has no constant for {@code 308 Permanent Redirect}. */
    private static final int HTTP_PERMANENT_REDIRECT = 308;

    /**
     * Thrown when a URL — or a URL it redirects to — is not one the server may fetch.
     */
    static final class UnsafeUrlException extends IOException {

        private static final long serialVersionUID = 1L;

        UnsafeUrlException(URL url) {
            super("Refusing to fetch " + url + ": it does not use http or https, or it resolves to "
                    + "an internal or special-purpose address. Set " + ALLOW_ANY_ADDRESS_PROPERTY
                    + "=true if this host is intentionally on an internal address.");
        }
    }

    /**
     * Thrown when an {@code https} URL redirects to one that is not {@code https}, which would
     * fetch the partner's metadata — and the keys in it — in cleartext.
     */
    static final class InsecureRedirectException extends IOException {

        private static final long serialVersionUID = 1L;

        InsecureRedirectException(URL from, URL to) {
            super("Refusing to follow a redirect from " + from + " to " + to + ": it leaves https");
        }
    }

    /**
     * Thrown when the last hop answers with a status other than {@code 200}.
     */
    static final class ErrorResponseException extends IOException {

        private static final long serialVersionUID = 1L;

        private final int status;

        ErrorResponseException(URL url, int status) {
            super(url + " returned " + status);
            this.status = status;
        }

        int getStatus() {
            return status;
        }
    }

    private final int timeout;

    /**
     * Constructor.
     *
     * @param timeout the connect and read timeout of each hop, in milliseconds.
     */
    MetadataUrlFetcher(int timeout) {
        this.timeout = timeout;
    }

    /**
     * Fetches {@code url} and returns its body, the lines read concatenated without separators.
     *
     * @param url the URL to fetch.
     * @return the body of the response.
     * @throws UnsafeUrlException if the URL, or any URL it redirects to, is not safe to fetch.
     * @throws InsecureRedirectException if an {@code https} URL redirects to a non-{@code https} one.
     * @throws ErrorResponseException if the response is neither a redirect nor {@code 200}.
     * @throws MalformedURLException if the URL or a redirect {@code Location} is not a valid URL.
     * @throws IOException if the redirect budget is exhausted or the fetch itself fails.
     */
    String fetch(String url) throws IOException {
        URL target = new URL(url);
        for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
            if (!isSafe(target)) {
                if (isHttp(target)) {
                    // A host that does not resolve is unreachable, not unsafe: the validator refuses
                    // it all the same, so resolve it here and let UnknownHostException, an
                    // IOException, be reported as unreachable.
                    InetAddress.getAllByName(target.getHost());
                }
                throw new UnsafeUrlException(target);
            }
            final HttpURLConnection connection = open(target);
            try {
                connection.setRequestMethod("GET");
                connection.setInstanceFollowRedirects(false);
                connection.setConnectTimeout(timeout);
                connection.setReadTimeout(timeout);
                final int status = connection.getResponseCode();
                if (isRedirect(status)) {
                    final URL next = redirectTarget(connection, target);
                    if (!isAllowedHop(target, next)) {
                        throw new InsecureRedirectException(target, next);
                    }
                    target = next;
                    continue;
                }
                if (status != HttpURLConnection.HTTP_OK) {
                    throw new ErrorResponseException(target, status);
                }
                return readBody(connection);
            } finally {
                connection.disconnect();
            }
        }
        throw new IOException("Gave up fetching " + url + " after " + MAX_REDIRECTS + " redirects");
    }

    /**
     * Whether the server may fetch {@code url}.
     *
     * <p>Visible for testing: the address blocklist rejects the loopback address that a test HTTP
     * server necessarily listens on.
     *
     * @param url the URL about to be fetched — the original one or a redirect target.
     * @return {@code true} if the URL is safe for the server to fetch.
     */
    boolean isSafe(URL url) {
        if (!isHttp(url)) {
            return false;
        }
        return SystemProperties.getAsBoolean(ALLOW_ANY_ADDRESS_PROPERTY, false)
                || SsrfUrlValidator.isSafeRemoteUrl(url.toExternalForm());
    }

    /**
     * Opens the connection for one hop.
     *
     * <p>Visible for testing: the test HTTP server speaks only plain {@code http}.
     *
     * @param target the URL of the hop, already checked by {@link #isSafe(URL)}.
     * @return the connection, not yet connected.
     * @throws IOException if the connection cannot be opened.
     */
    HttpURLConnection open(URL target) throws IOException {
        return (HttpURLConnection) target.openConnection();
    }

    /**
     * Whether a redirect from {@code from} to {@code to} may be followed, as far as the scheme goes:
     * {@code http} to {@code https} is an upgrade and is allowed, but a redirect never leaves
     * {@code https}. The address of {@code to} is checked separately by {@link #isSafe(URL)}.
     *
     * @param from the URL that answered with the redirect.
     * @param to the redirect target.
     * @return {@code false} if the redirect leaves {@code https}.
     */
    static boolean isAllowedHop(URL from, URL to) {
        return !"https".equalsIgnoreCase(from.getProtocol()) || "https".equalsIgnoreCase(to.getProtocol());
    }

    private static boolean isHttp(URL url) {
        final String protocol = url.getProtocol();
        return "http".equalsIgnoreCase(protocol) || "https".equalsIgnoreCase(protocol);
    }

    private static boolean isRedirect(int status) {
        return status == HttpURLConnection.HTTP_MULT_CHOICE
                || status == HttpURLConnection.HTTP_MOVED_PERM
                || status == HttpURLConnection.HTTP_MOVED_TEMP
                || status == HttpURLConnection.HTTP_SEE_OTHER
                || status == HTTP_TEMPORARY_REDIRECT
                || status == HTTP_PERMANENT_REDIRECT;
    }

    private static URL redirectTarget(HttpURLConnection connection, URL current) throws IOException {
        final String location = connection.getHeaderField("Location");
        if (location == null || location.trim().isEmpty()) {
            throw new IOException(current + " returned a redirect without a Location header");
        }
        // Resolve against the current URL so that a relative Location is handled the way the
        // automatic redirect follower would have handled it.
        return new URL(current, location);
    }

    private static String readBody(HttpURLConnection connection) throws IOException {
        final StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
        }
        return content.toString();
    }
}
