/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2006 Sun Microsystems Inc. All Rights Reserved
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
 * $Id: Status.java,v 1.2 2008/06/25 05:47:58 qcheng Exp $
 *
 * Portions Copyrighted 2019 Open Source Solution Technology Corporation
 */


package com.sun.identity.saml2.protocol;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.protocol.impl.StatusImpl;

/**
 * This class represents the <code>StatusType</code> complex type in
 * SAML protocol schema.
 *
 * <pre>
 * &lt;complexType name="StatusType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:protocol}StatusMessage" minOccurs="0"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:protocol}StatusDetail" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 *
 * @supported.all.api
 */

@JsonDeserialize(as=StatusImpl.class)
public interface Status {
    
    /**
     * Returns the value of the statusCode property.
     *
     * @return the value of the statusCode property
     * @see #setStatusCode(StatusCode)
     */
    public com.sun.identity.saml2.protocol.StatusCode getStatusCode();
    
    /**
     * Sets the value of the statusCode property.
     *
     * @param value the value of the statusCode property to be set
     * @throws SAML2Exception if the object is immutable
     * @see #getStatusCode
     */
    public void setStatusCode(com.sun.identity.saml2.protocol.StatusCode value)
    throws SAML2Exception;
    
    /**
     * Returns the value of the statusMessage property.
     *
     * @return the value of the statusMessage property
     * @see #setStatusMessage(String)
     */
    public java.lang.String getStatusMessage();
    
    /**
     * Sets the value of the statusMessage property.
     *
     * @param value the value of the statusMessage property to be set
     * @throws SAML2Exception if the object is immutable
     * @see #getStatusMessage
     */
    public void setStatusMessage(java.lang.String value)
    throws SAML2Exception;
    
    /**
     * Returns the value of the statusDetail property.
     *
     * @return the value of the statusDetail property
     * @see #setStatusDetail(StatusDetail)
     */
    public com.sun.identity.saml2.protocol.StatusDetail getStatusDetail();
    
    /**
     * Sets the value of the statusDetail property.
     *
     * @param value the value of the statusDetail property to be set
     * @throws SAML2Exception if the object is immutable
     * @see #getStatusDetail
     */
    public void setStatusDetail(
    com.sun.identity.saml2.protocol.StatusDetail value)
    throws SAML2Exception;
    
    /**
     * Returns the <code>Status</code> in an XML document String format
     * based on the <code>Status</code> schema described above.
     *
     * @return An XML String representing the <code>Status</code>.
     * @throws SAML2Exception if some error occurs during conversion to
     *         <code>String</code>.
     */
    public String toXMLString() throws SAML2Exception;
    
    /**
     * Returns the <code>Status</code> in an XML document String format
     * based on the <code>Status</code> schema described above.
     *
     * @param includeNSPrefix Determines whether or not the namespace qualifier 
     * is prepended to the Element when converted
     * @param declareNS Determines whether or not the namespace is declared
     *        within the Element.
     * @return A XML String representing the <code>Status</code>.
     * @throws SAML2Exception if some error occurs during conversion to
     *         <code>String</code>.
     */
    public String toXMLString(boolean includeNSPrefix, boolean declareNS)
    throws SAML2Exception;    
    
    /**
     * Makes the obejct immutable
     */
    public void makeImmutable();
    
    /**
     * Returns true if the object is mutable, false otherwise
     *
     * @return true if the object is mutable, false otherwise
     */
    public boolean isMutable();
}
