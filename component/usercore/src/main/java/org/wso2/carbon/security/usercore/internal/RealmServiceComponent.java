/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.security.usercore.internal;

import org.apache.log4j.Logger;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.security.user.core.common.CarbonRealmServiceImpl;
import org.wso2.carbon.security.usercore.service.RealmService;
import org.wso2.carbon.security.usercore.service.RealmService;

/**
 * OSGI Component which handles the User Management.
 */
@Component(
        name = "RealmServiceComponent",
        immediate = true
)
public class RealmServiceComponent {

    private Logger log = Logger.getLogger(RealmServiceComponent.class);
    private ServiceRegistration registration;

    @Activate
    public void registerRealmService(BundleContext bundleContext) {

        try {
            registration = bundleContext.registerService(RealmService.class.getName(),
                    CarbonRealmServiceImpl.getInstance(), null);
        } catch (Throwable t) {
            log.error(t);
        }
    }

    @Deactivate
    public void unregisterRealmService(BundleContext bundleContext) {

        try {
            bundleContext.ungetService(registration.getReference());
        } catch (Throwable t) {
            log.error(t);
        }
    }
}
