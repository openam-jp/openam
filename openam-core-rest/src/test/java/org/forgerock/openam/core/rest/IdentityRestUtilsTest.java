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
 * Portions copyright 2026 OSSTech Corporation.
 */
package org.forgerock.openam.core.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.openam.core.rest.IdentityRestUtils.AGENT_TYPE;
import static org.forgerock.openam.core.rest.IdentityRestUtils.GROUP_TYPE;
import static org.forgerock.openam.core.rest.IdentityRestUtils.USER_TYPE;
import static org.forgerock.openam.core.rest.IdentityRestUtils.enforceSelfRegistrationWhiteList;
import static org.forgerock.openam.core.rest.IdentityRestUtils.enforceWhiteList;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.forgerock.guice.core.GuiceTestCase;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.BadRequestException;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.json.resource.ResourceException;
import org.forgerock.openam.core.rest.UserAttributeInfo.UserAttributeInfoBuilder;
import org.forgerock.openam.rest.RealmContext;
import org.forgerock.openam.sm.config.ConsoleConfigHandler;
import org.forgerock.selfservice.core.SelfServiceContext;
import org.forgerock.services.context.Context;
import org.forgerock.services.context.RootContext;
import org.testng.annotations.Test;

import com.google.inject.Binder;

/**
 * Tests the self service attribute whitelist, which is the only thing standing between an anonymous caller and the
 * system admin token that creates the identity.
 *
 * {@link IdentityRestUtils} asks the injector for its exception mapping handler from a static initialiser, so the
 * class runs as a {@link GuiceTestCase}, which keeps the Guice modules on the classpath - loading them needs a
 * configured OpenAM - out of the injector it builds.
 */
public class IdentityRestUtilsTest extends GuiceTestCase {

    private static final String REALM = "/";

    /** The out of the box value of the selfServiceUserRegistrationValidUserAttributes setting. */
    private static final Set<String> DEFAULT_WHITELIST = new HashSet<>(Arrays.asList(
            "mail", "inetUserStatus", "sn", "username", "userPassword", "kbaInfo", "givenName"));

    @Override
    public void configure(Binder binder) {
        // Nothing to bind: what the class under test asks the injector for is created just in time.
    }

    @Test
    public void shouldAcceptWhitelistedAttributes() throws Exception {
        enforceWhiteList(REALM, json(object(
                field("username", "demo"),
                field("mail", "demo@example.com"),
                field("sn", "demo"),
                field("givenName", "demo"))), USER_TYPE, DEFAULT_WHITELIST);
    }

    /**
     * The whitelist is configured in camel case while REST clients, and OpenAM's own documentation for the legacy
     * self-registration flow, spell the very same attributes in lower case.
     */
    @Test
    public void shouldAcceptWhitelistedAttributesWhateverTheCase() throws Exception {
        enforceWhiteList(REALM, json(object(
                field("username", "demo"),
                field("userpassword", "s3cr3t"),
                field("mail", "demo@example.com"))), USER_TYPE, DEFAULT_WHITELIST);
    }

    @Test
    public void shouldRejectAttributeThatIsNotWhitelisted() {
        JsonValue user = json(object(
                field("username", "demo"),
                field("telephonenumber", "555-2368")));

        assertRejected(user, DEFAULT_WHITELIST, "telephonenumber");
    }

    /**
     * GHSA-jv8f-m88g-h6mm: a group membership in the user object must not get past the whitelist, or a self
     * registering user could join an administrator group.
     */
    @Test
    public void shouldRejectGroupMembershipThatIsNotWhitelisted() {
        JsonValue user = json(object(
                field("username", "demo"),
                field("mail", "demo@example.com"),
                field("memberof", array("cn=admins,ou=groups,dc=openam,dc=example,dc=com"))));

        assertRejectedAsMembership(user, DEFAULT_WHITELIST, "memberof");
    }

    /**
     * jsonValueToIdentityDetails hands memberof on as an ordinary attribute in any spelling, so the attribute loop
     * would reject this one as well.  Asserting that the membership check is the one that answers pins that the
     * rejection does not depend on how the conversion treats memberof.
     */
    @Test
    public void shouldRejectGroupMembershipWhateverTheCase() {
        JsonValue user = json(object(
                field("username", "demo"),
                field("MemberOf", array("admins"))));

        assertRejectedAsMembership(user, DEFAULT_WHITELIST, "MemberOf");
    }

    @Test
    public void shouldAcceptGroupMembershipWhenWhitelisted() throws Exception {
        Set<String> whiteList = new HashSet<>(DEFAULT_WHITELIST);
        whiteList.add("memberof");

        enforceWhiteList(REALM, json(object(
                field("username", "demo"),
                field("memberof", array("staff")))), USER_TYPE, whiteList);
    }

    /**
     * jsonValueToIdentityDetails swallows a body it cannot convert and returns before it sets the attributes, which
     * used to leave this method dereferencing null on a request no one had to authenticate to make.
     */
    @Test
    public void shouldRejectAUserObjectThatCannotBeConverted() {
        JsonValue user = json(object(
                field("username", 42),
                field("telephonenumber", "555-2368")));

        try {
            enforceWhiteList(REALM, user, USER_TYPE, DEFAULT_WHITELIST);
            fail("Expected a BadRequestException");
        } catch (BadRequestException e) {
            assertThat(e.getMessage()).contains("Invalid user object");
        }
    }

    @Test
    public void shouldRejectEmptyWhiteList() {
        JsonValue user = json(object(field("username", "demo")));

        try {
            enforceWhiteList(REALM, user, USER_TYPE, new HashSet<String>());
            fail("Expected a BadRequestException");
        } catch (BadRequestException e) {
            assertThat(e.getMessage()).contains("whitelist");
        }
    }

    @Test
    public void shouldNotApplyWhiteListToOtherIdentityTypes() throws Exception {
        JsonValue group = json(object(
                field("username", "admins"),
                field("uniqueMember", "uid=demo,ou=people,dc=openam,dc=example,dc=com")));

        enforceWhiteList(REALM, group, GROUP_TYPE, DEFAULT_WHITELIST);
        enforceWhiteList(REALM, group, AGENT_TYPE, DEFAULT_WHITELIST);
    }

    /**
     * The context the whitelist keys off is the SelfServiceContext, not the RealmContext that a request carrying one
     * necessarily also has.  So the context here is given a RealmContext, the way a request reaching the users
     * endpoint has one: what is left out is the SelfServiceContext alone, and removing the guard is answered by the
     * whitelist's own rejection of telephonenumber.
     */
    @Test
    public void shouldNotApplyWhiteListOutsideOfASelfServiceContext() throws Exception {
        JsonValue user = json(object(
                field("username", "demo"),
                field("telephonenumber", "555-2368"),
                field("memberof", array("admins"))));

        enforceWhiteList(new RealmContext(new RootContext()), user, USER_TYPE, DEFAULT_WHITELIST);
    }

    /**
     * GHSA-jv8f-m88g-h6mm: the user registration flow of the self service framework creates the identity with the
     * system admin token, so a group membership smuggled into its user object has to be rejected here.
     */
    @Test
    public void shouldRejectGroupMembershipWithinASelfServiceContext() {
        Context context = new SelfServiceContext(new RealmContext(new RootContext()));
        JsonValue user = json(object(
                field("username", "demo"),
                field("memberof", array("admins"))));

        try {
            enforceWhiteList(context, user, USER_TYPE, DEFAULT_WHITELIST);
            fail("Expected a BadRequestException");
        } catch (BadRequestException e) {
            assertThat(e.getMessage()).contains("memberof");
        }
    }

    /**
     * Not a state SMS produces: selfService.xml ships seven default values for the setting, restored whenever the key
     * is absent, and the config handler refuses an absent key before it consults required() - see UserAttributeInfo.
     * What this pins is the guard in enforceWhiteList for a whitelist that reaches it empty anyway: a builder whose
     * setter was never called, as a caller other than the config handler might hand it, is refused by name.
     */
    @Test
    public void shouldRejectAClearedWhiteList() {
        ConsoleConfigHandler configHandler = mock(ConsoleConfigHandler.class);
        given(configHandler.getConfig(REALM, UserAttributeInfoBuilder.class)).willReturn(clearedWhiteList());

        try {
            enforceSelfRegistrationWhiteList(configHandler, REALM, json(object(field("username", "demo"))),
                    USER_TYPE);
            fail("Expected a BadRequestException");
        } catch (ResourceException e) {
            assertThat(e).isInstanceOf(BadRequestException.class);
            assertThat(e.getMessage()).contains("whitelist");
        }
    }

    /**
     * The whitelist is read from the self service SMS service, which fails with an unchecked exception for a realm
     * it is not configured for.  The check has to stay closed and say which one failed, without handing the service
     * configuration's own text to a caller that needed no session to get here.
     */
    @Test
    public void shouldReportAWhiteListThatCannotBeReadAsAnInternalError() {
        ConsoleConfigHandler configHandler = mock(ConsoleConfigHandler.class);
        given(configHandler.getConfig(REALM, UserAttributeInfoBuilder.class)).willThrow(
                new IllegalArgumentException("Expected attribute selfServiceUserRegistrationValidUserAttributes"));

        try {
            enforceSelfRegistrationWhiteList(configHandler, REALM, json(object(field("username", "demo"))),
                    USER_TYPE);
            fail("Expected an InternalServerErrorException");
        } catch (ResourceException e) {
            assertThat(e).isInstanceOf(InternalServerErrorException.class);
            assertThat(e.getMessage()).doesNotContain("selfServiceUserRegistrationValidUserAttributes");
        }
    }

    /** A builder whose whitelist setter was never called. */
    private static UserAttributeInfo clearedWhiteList() {
        UserAttributeInfoBuilder builder = new UserAttributeInfoBuilder();
        builder.setProtectedUpdateAttributes(Collections.<String>emptySet());
        return builder.build(Collections.<String, Set<String>>emptyMap());
    }

    private void assertRejected(JsonValue user, Set<String> whiteList, String expectedAttribute) {
        try {
            enforceWhiteList(REALM, user, USER_TYPE, whiteList);
            fail("Expected a BadRequestException for " + expectedAttribute);
        } catch (BadRequestException e) {
            assertThat(e.getMessage()).contains(expectedAttribute);
        }
    }

    private void assertRejectedAsMembership(JsonValue user, Set<String> whiteList, String expectedAttribute) {
        try {
            enforceWhiteList(REALM, user, USER_TYPE, whiteList);
            fail("Expected a BadRequestException for " + expectedAttribute);
        } catch (BadRequestException e) {
            assertThat(e.getMessage()).contains("Group membership " + expectedAttribute);
        }
    }
}
