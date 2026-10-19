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
package org.forgerock.openam.upgrade.steps;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.MockitoAnnotations.initMocks;

import java.security.PrivilegedAction;
import java.util.ResourceBundle;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import org.forgerock.openam.sm.datalayer.api.ConnectionFactory;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;

/**
 * The step deactivates the {@code demo} user only where it still exists, is still active, and still answers to
 * the password the configurator gave it, and it reports what it could not switch off rather than failing the
 * upgrade over it.
 */
public class DeactivateDefaultCredentialsStepTest {

    private static final String DEMO = "demo";
    /**
     * The password the configurator gave {@code demo}. Keep in step with
     * {@code DeactivateDefaultCredentialsStep.INSTALLATION_DEFAULTS}: a value that drifts silently would
     * deactivate nothing on upgrade and the suite would stay green.
     */
    private static final String DEMO_PASSWORD = "changeit";

    @Mock
    private PrivilegedAction<SSOToken> adminTokenAction;
    @Mock
    private ConnectionFactory connectionFactory;
    @Mock
    private AMIdentityRepository repository;

    private AMIdentity demo;
    /** Whether the repository still accepts the installation default password of {@code demo}. */
    private boolean acceptsItsInstallationPassword;
    /** Whether the repository refuses the login with an exception rather than with a plain {@code false}. */
    private boolean refusesTheLogin;

    private TestStep upgradeStep;

    @BeforeMethod
    public void setup() throws Exception {
        initMocks(this);
        acceptsItsInstallationPassword = false;
        refusesTheLogin = false;

        // Absent unless the test says otherwise, which is the state of a store the configurator never
        // created it in.
        demo = mock(AMIdentity.class, DEMO);
        given(demo.isExists()).willReturn(false);
        given(repository.authenticate(any(IdType.class), any(Callback[].class)))
                .willAnswer(this::answerAuthentication);

        upgradeStep = new TestStep(adminTokenAction, connectionFactory, repository, demo);
    }

    @Test
    public void shouldDeactivateDemoWhereItStillAcceptsItsInstallationPassword() throws Exception {
        givenDemo(true, true);
        acceptsItsInstallationPassword = true;

        upgradeStep.initialize();

        assertThat(upgradeStep.isApplicable()).isTrue();

        upgradeStep.perform();

        verify(demo).setActiveStatus(false);
        assertThat(reportLineForDemo()).isNotNull();
    }

    @Test
    public void shouldLeaveDemoAloneWhereItNoLongerUsesThatPassword() throws Exception {
        givenDemo(true, true);

        upgradeStep.initialize();

        assertThat(upgradeStep.isApplicable()).isFalse();
        verify(demo, never()).setActiveStatus(anyBoolean());
    }

    @Test
    public void shouldLeaveDemoAloneWhereItIsAlreadyInactive() throws Exception {
        givenDemo(true, false);
        acceptsItsInstallationPassword = true;

        upgradeStep.initialize();

        assertThat(upgradeStep.isApplicable()).isFalse();
        // Not even asked: an inactive identity cannot authenticate whatever its password is, and the
        // upgrade has no business binding as it.
        verify(repository, never()).authenticate(any(IdType.class), any(Callback[].class));
    }

    @Test
    public void shouldLeaveDemoAloneWhereItDoesNotExist() throws Exception {
        // The guard reads isExists AND isActive; pinning isActive=true stops a mutant that skips the
        // isExists check from being covered by Mockito's default false return.
        given(demo.isActive()).willReturn(true);
        acceptsItsInstallationPassword = true;

        upgradeStep.initialize();

        assertThat(upgradeStep.isApplicable()).isFalse();
        verify(repository, never()).authenticate(any(IdType.class), any(Callback[].class));
    }

    @Test
    public void shouldLeaveDemoAloneWhereTheRepositoryRefusesToAuthenticateIt() throws Exception {
        givenDemo(true, true);
        refusesTheLogin = true;

        upgradeStep.initialize();

        assertThat(upgradeStep.isApplicable()).isFalse();
        verify(demo, never()).setActiveStatus(anyBoolean());
    }

    @Test
    public void shouldLeaveDemoAloneWhereItsRepositoryFails() throws Exception {
        givenDemo(true, true);
        acceptsItsInstallationPassword = true;
        // A repository that cannot answer is not evidence that the credential is still in place: the
        // step must not deactivate the account on the strength of a failure.
        doThrow(new IdRepoException("the store is down"))
                .when(repository).authenticate(eq(IdType.USER), any(Callback[].class));

        upgradeStep.initialize();

        assertThat(upgradeStep.isApplicable()).isFalse();
        verify(demo, never()).setActiveStatus(anyBoolean());
    }

    @Test
    public void shouldReportDemoWhereItCouldNotBeDeactivatedRatherThanFailingTheUpgrade() throws Exception {
        givenDemo(true, true);
        acceptsItsInstallationPassword = true;
        // Deleted between the two phases, say.
        doThrow(new IdRepoException("no such object")).when(demo).setActiveStatus(false);

        upgradeStep.initialize();
        upgradeStep.perform();

        String notDeactivated = ResourceBundle.getBundle("amUpgrade")
                .getString("upgrade.defaultcredentials.notdeactivated");
        assertThat(reportLineForDemo()).contains(notDeactivated).contains("no such object");
        verify(demo, times(3)).setActiveStatus(false);
        assertThat(upgradeStep.pauses).isEqualTo(2);
    }

    /**
     * The plugin the first attempt is served can be shut down under it by the notification of an earlier step's
     * change to the identity repository service; the load balancer of a closed plugin throws a
     * NullPointerException. A later attempt is served the plugin that replaced it.
     */
    @Test
    public void shouldDeactivateDemoWhereAnAttemptHitsAPluginBeingShutDown() throws Exception {
        givenDemo(true, true);
        acceptsItsInstallationPassword = true;
        doThrow(new NullPointerException()).doNothing().when(demo).setActiveStatus(false);

        upgradeStep.initialize();
        upgradeStep.perform();

        verify(demo, times(2)).setActiveStatus(false);
        assertThat(upgradeStep.pauses).isEqualTo(1);
        assertThat(reportLineForDemo()).endsWith(" " + DEMO);
    }

    @Test
    public void shouldReportDemoRatherThanFailingTheUpgradeWhereEveryAttemptHitsARuntimeException()
            throws Exception {
        givenDemo(true, true);
        acceptsItsInstallationPassword = true;
        doThrow(new NullPointerException()).when(demo).setActiveStatus(false);

        upgradeStep.initialize();
        upgradeStep.perform();

        String notDeactivated = ResourceBundle.getBundle("amUpgrade")
                .getString("upgrade.defaultcredentials.notdeactivated");
        assertThat(reportLineForDemo()).contains(notDeactivated).contains("NullPointerException");
        verify(demo, times(3)).setActiveStatus(false);
    }

    @Test
    public void shouldStopRetryingWhereTheUpgradeIsInterrupted() throws Exception {
        givenDemo(true, true);
        acceptsItsInstallationPassword = true;
        doThrow(new IdRepoException("the store is down")).when(demo).setActiveStatus(false);
        upgradeStep.interrupted = true;

        upgradeStep.initialize();
        upgradeStep.perform();

        verify(demo, times(1)).setActiveStatus(false);
        assertThat(reportLineForDemo()).contains("the store is down");
    }

    private Object answerAuthentication(InvocationOnMock invocation) throws AuthLoginException {
        final IdType type = invocation.getArgument(0);
        final Callback[] callbacks = invocation.getArgument(1);
        final String name = ((NameCallback) callbacks[0]).getName();
        final String password = new String(((PasswordCallback) callbacks[1]).getPassword());
        if (refusesTheLogin) {
            throw new AuthLoginException("the password is not the one the configurator set");
        }
        // Pin what the step offers: the name, the exact installation password, and the identity type it
        // authenticates as.
        return acceptsItsInstallationPassword
                && DEMO.equals(name)
                && DEMO_PASSWORD.equals(password)
                && IdType.USER.equals(type);
    }

    private void givenDemo(boolean exists, boolean active) throws Exception {
        given(demo.isExists()).willReturn(exists);
        given(demo.isActive()).willReturn(active);
    }

    /**
     * The line the detailed report devotes to {@code demo}, or {@code null} where it does not mention it.
     * The report names an identity as "&lt;type&gt; &lt;name&gt;", followed by the reason where the step
     * could not switch it off.
     */
    private String reportLineForDemo() {
        for (String line : upgradeStep.getDetailedReport("\n").split("\n")) {
            if (line.startsWith("* ") && (line.endsWith(" " + DEMO) || line.contains(" " + DEMO + " - "))) {
                return line;
            }
        }
        return null;
    }

    /**
     * Replaces the two pieces of the step that reach the identity repository.
     */
    private static final class TestStep extends DeactivateDefaultCredentialsStep {

        private final AMIdentityRepository repository;
        private final AMIdentity demo;
        /** How many times the step waited before trying again. */
        private int pauses;
        /** Whether the wait is cut short as by an interrupt of the upgrade thread. */
        private boolean interrupted;

        private TestStep(PrivilegedAction<SSOToken> adminTokenAction, ConnectionFactory connectionFactory,
                AMIdentityRepository repository, AMIdentity demo) {
            super(adminTokenAction, connectionFactory);
            this.repository = repository;
            this.demo = demo;
        }

        @Override
        protected AMIdentityRepository getIdentityRepository() {
            return repository;
        }

        @Override
        protected AMIdentity identityOf(IdType identityType, String name) {
            // Pin what the step looks up: demo, as a USER, and nothing else.
            assertThat(name).isEqualTo(DEMO);
            assertThat(identityType).isEqualTo(IdType.USER);
            return demo;
        }

        @Override
        protected boolean pauseBeforeRetry() {
            // No waiting in a test: only count the pauses.
            pauses++;
            return !interrupted;
        }
    }
}
