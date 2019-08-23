/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 2018 Open Source Solution Technology,Corp.
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 */



package jp.co.osstech.openam.authentication.modules.webauthn;


import java.security.Principal;
//import java.io.Serializable;


/**
 * This class implements the <code>Principal</code> interface
 * and represents an Webauthn user.
 * <p>
 Principals such as this <code>WebauthnPrincipal</code>
 * may be associated with a particular <code>Subject</code>
 * to augment that <code>Subject</code> with an additional
 * identity.  Refer to the <code>Subject</code> class for more information
 * on how to achieve this.  Authorization decisions can then be based upon 
 * the Principals associated with a <code>Subject</code>.
 */
public class WebauthnPrincipal implements Principal, java.io.Serializable {

    private String name;

    /**
     * Creates a <code>WebauthnPrincipal</code> with a Webauthn user name.
     *
     * @param name the Webauthn user name for this user.
     * @exception NullPointerException if the <code>name</code> is
     *            <code>null</code>.
     */
    public WebauthnPrincipal(String name) {
        if (name == null) {
            throw new NullPointerException("illegal null input");
        }

        this.name = name;
    }

    /**
     * Returns the Webauthn user name for this 
     * <code>WebauthnPrincipal</code>.
     *
     * @return the Webauthn user name for this 
     *         <code>WebauthnPrincipal</code>
     */
    public String getName() {
        return name;
    }

    /**
     * Returns a string representation of this 
     * <code>WebauthnPrincipal</code>.
     *
     * @return a string representation of this
     *         <code>WebauthnPrincipal</code>.
     */
    public String toString() {
        return("WebauthnPrincipal: " + name);
    }

    /**
     * Compares the specified Object with this <code>WebauthnPrincipal
     * </code> for equality.  Returns true if the given object is also a
     * <code>WebauthnPrincipal</code> and the two
     * <code>WebauthnPrincipals</code> have the same user name.
     *
     * @param o Object to be compared for equality with this
     *        <code>WebauthnPrincipal</code>.
     * @return true if the specified Object is equal equal to this
     *         <code>WebauthnPrincipal</code>.
     */
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }

        if (this == o) {
            return true;
        }
 
        if (!(o instanceof WebauthnPrincipal)) {
            return false;
        }
        
        WebauthnPrincipal that = (WebauthnPrincipal)o;
        return this.getName().equals(that.getName());
    }
 
    /**
     * Returns a hash code for this <code>WebauthnPrincipal</code>.
     *
     * @return a hash code for this <code>WebauthnPrincipal</code>.
     */
    public int hashCode() {
        return name.hashCode();
    }
}
