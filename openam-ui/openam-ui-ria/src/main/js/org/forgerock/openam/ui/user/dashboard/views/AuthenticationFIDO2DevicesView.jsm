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

import $ from "jquery";
import _ from "lodash";

import {
    remove as removeFido2,
    getAll as getAllFido2
} from "org/forgerock/openam/ui/user/dashboard/services/FIDO2DeviceService";
import AbstractView from "org/forgerock/commons/ui/common/main/AbstractView";
import FIDO2DeviceDetailsDialog from "org/forgerock/openam/ui/user/dashboard/views/FIDO2DeviceDetailsDialog";
import Messages from "org/forgerock/commons/ui/common/components/Messages";

const getAttributeFromElement = (element, attribute) => $(element).closest(`div[${attribute}]`).attr(attribute);
const getUUIDFromElement = (element) => getAttributeFromElement(element, "data-device-uuid");
const handleReject = (response) => {
    Messages.addMessage({
        type: Messages.TYPE_DANGER,
        response
    });
};

class FIDO2DeviceManagementView extends AbstractView {
    constructor () {
        super();
        this.template = "templates/user/dashboard/AuthenticationFIDO2DevicesTemplate.html";
        this.noBaseTemplate = true;
        this.element = "#authenticationFIDO2Devices";
        this.events = {
            "click [data-delete]":  "handleDelete",
            "click [data-details]": "handleShowDeviceDetails"
        };
    }
    handleDelete (event) {
        event.preventDefault();

        const uuid = getUUIDFromElement(event.currentTarget);
        const deleteFunc = removeFido2;

        deleteFunc(uuid).then(() => {
            this.render();
        }, handleReject);
    }
    handleShowDeviceDetails (event) {
        event.preventDefault();

        const uuid = getUUIDFromElement(event.currentTarget);
        const device = _.find(this.data.devices, { uuid });

        FIDO2DeviceDetailsDialog(uuid, device);
    }
    render () {
        var self = this;

        getAllFido2().then(function (value) {
            self.data.devices = _.map(value, function (device) {
                return {
                    deviceName: device.deviceName,
                    uuid: device.uuid,
                    createdDate: new Date(device.createdDate).toLocaleString(),
                    type: "fidoe2",
                    icon: "key"
                };
            });
            self.parentRender();
        }, handleReject);
    }
}

export default new FIDO2DeviceManagementView();
