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
 * Copyright 2019 Open Source Solution Technology Corporation
 */

package jp.co.osstech.openam.authentication.modules.webauthn;

import java.security.Principal;
//import java.io.Serializable;

/**
 * This class implements the <code>Principal</code> interface and represents an
 * WebAuthn user.
 * <p>
 * Principals such as this <code>WebAuthnPrincipal</code> may be associated with
 * a particular <code>Subject</code> to augment that <code>Subject</code> with
 * an additional identity. Refer to the <code>Subject</code> class for more
 * information on how to achieve this. Authorization decisions can then be based
 * upon the Principals associated with a <code>Subject</code>.
 */
public class WebAuthnPrincipal implements Principal, java.io.Serializable {

    private String name;

    /**
     * Creates a <code>WebAuthnPrincipal</code> with a WebAuthn user name.
     *
     * @param name the WebAuthn user name for this user.
     * @exception NullPointerException if the <code>name</code> is
     *                                 <code>null</code>.
     */
    public WebAuthnPrincipal(String name) {
        if (name == null) {
            throw new NullPointerException("illegal null input");
        }

        this.name = name;
    }

    /**
     * Returns the WebAuthn user name for this <code>WebAuthnPrincipal</code>.
     *
     * @return the WebAuthn user name for this <code>WebAuthnPrincipal</code>
     */
    public String getName() {
        return name;
    }

    /**
     * Returns a string representation of this <code>WebAuthnPrincipal</code>.
     *
     * @return a string representation of this <code>WebAuthnPrincipal</code>.
     */
    public String toString() {
        return ("WebAuthnPrincipal: " + name);
    }

    /**
     * Compares the specified Object with this <code>WebAuthnPrincipal
     * </code> for equality. Returns true if the given object is also a
     * <code>WebAuthnPrincipal</code> and the two <code>WebAuthnPrincipals</code>
     * have the same user name.
     *
     * @param o Object to be compared for equality with this
     *          <code>WebAuthnPrincipal</code>.
     * @return true if the specified Object is equal equal to this
     *         <code>WebAuthnPrincipal</code>.
     */
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }

        if (this == o) {
            return true;
        }

        if (!(o instanceof WebAuthnPrincipal)) {
            return false;
        }

        WebAuthnPrincipal that = (WebAuthnPrincipal) o;
        return this.getName().equals(that.getName());
    }

    /**
     * Returns a hash code for this <code>WebAuthnPrincipal</code>.
     *
     * @return a hash code for this <code>WebAuthnPrincipal</code>.
     */
    public int hashCode() {
        return name.hashCode();
    }
}
