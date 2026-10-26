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

package org.forgerock.oauth2.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.forgerock.openam.rest.representations.JacksonRepresentationFactory;
import org.restlet.Request;
import org.restlet.data.Form;
import org.restlet.data.MediaType;
import org.restlet.data.Method;
import org.restlet.representation.InputRepresentation;
import org.restlet.representation.Representation;
import org.testng.annotations.Test;

/**
 * Tests {@link OAuth2Request#getBodyParameter}, which reads a request body parameter apart from a query string
 * one - something {@link OAuth2Request#getParameter} cannot do because it gives the query string priority.
 */
public class OAuth2RequestTest {

    private static final String URI = "http://openam.example.com:8080/openam/oauth2/authorize";

    private static final JacksonRepresentationFactory JACKSON =
            new JacksonRepresentationFactory(new ObjectMapper());

    private static OAuth2Request postWith(String query, String bodyDecision) {
        Request request = new Request(Method.POST, query == null ? URI : URI + "?" + query);
        if (bodyDecision != null) {
            Form form = new Form();
            form.add("decision", bodyDecision);
            request.setEntity(form.getWebRepresentation());
        }
        return new OAuth2Request(JACKSON, request);
    }

    /**
     * A body backed by a stream, the way one arriving over the network is: reading it consumes it, and only
     * the entity {@code OAuth2Request} puts back makes a second read possible. The form representation the
     * other fixtures use is a {@code StringRepresentation}, which re-reads for free and so cannot show this.
     */
    private static OAuth2Request postWithStreamedBody(String query, String body, MediaType mediaType) {
        Request request = new Request(Method.POST, query == null ? URI : URI + "?" + query);
        Representation entity = new InputRepresentation(
                new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)), mediaType);
        request.setEntity(entity);
        return new OAuth2Request(JACKSON, request);
    }

    @Test
    public void shouldReadTheFormEncodedBodyOnly() {
        //given
        OAuth2Request request = postWith("decision=allow", "deny");

        //when / then
        assertThat(request.getBodyParameter("decision")).isEqualTo("deny");
        assertThat(request.getBodyParameter("absent")).isNull();
    }

    /**
     * A JSON body has to answer the same question a form encoded one does: {@code getParameter} reads both,
     * so a client that posts its consent decision as JSON must not start being treated as a "Deny".
     */
    @Test
    public void shouldReadTheJsonBodyOnly() {
        //given
        OAuth2Request request = postWithStreamedBody("decision=allow",
                "{\"decision\":\"deny\"}", MediaType.APPLICATION_JSON);

        //when / then
        assertThat(request.getBodyParameter("decision")).isEqualTo("deny");
        assertThat(request.getBodyParameter("absent")).isNull();
    }

    @Test
    public void shouldNotReportABodyValueForAnUnreadableMediaType() {
        //given
        OAuth2Request request = postWithStreamedBody("decision=allow", "decision=deny", MediaType.TEXT_PLAIN);

        //when / then
        assertThat(request.getBodyParameter("decision")).isNull();
    }

    /**
     * Reading a streamed entity consumes it, so the body has to be restored for the reads that follow.
     * Production reads {@code csrf} through {@code getParameter} as well as the decision through this method:
     * without the restore the second read sees an empty form.
     */
    @Test
    public void shouldLeaveAStreamedBodyReadableAfterReadingIt() {
        //given
        OAuth2Request request = postWithStreamedBody(null, "csrf=TOKEN&decision=deny",
                MediaType.APPLICATION_WWW_FORM);

        //when the request is read in the order the consent endpoints read it
        assertThat(request.getBodyParameter("decision")).isEqualTo("deny");

        //then the body is still there
        assertThat(request.<String>getParameter("csrf")).isEqualTo("TOKEN");
        assertThat(request.getBodyParameter("decision")).isEqualTo("deny");
    }

    @Test
    public void shouldNotReportABodyValueWhenThereIsNoBody() {
        //given
        OAuth2Request request = postWith("decision=allow", null);

        //when / then
        assertThat(request.getBodyParameter("decision")).isNull();
    }

    @Test
    public void shouldNotReportABodyValueOnAGet() {
        //given
        Request restletRequest = new Request(Method.GET, URI + "?decision=allow");

        //when / then
        assertThat(new OAuth2Request(JACKSON, restletRequest).getBodyParameter("decision")).isNull();
    }

    /**
     * Pins the precedence the consent endpoints have to work around: a form that posts back to the URL it was
     * served from sends both, and this is the one {@code getParameter} would act on.
     */
    @Test
    public void shouldGiveTheQueryStringPriorityOverTheBody() {
        //given
        OAuth2Request request = postWith("decision=allow", "deny");

        //when / then
        assertThat(request.<String>getParameter("decision")).isEqualTo("allow");
    }
}
