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

package org.wso2.carbon.security.caas.internal.osgi;

import org.osgi.framework.Bundle;
import org.osgi.framework.PrototypeServiceFactory;
import org.osgi.framework.ServiceRegistration;
import org.wso2.carbon.security.caas.api.CarbonCallbackHandler;
import org.wso2.carbon.security.caas.api.handler.UsernamePasswordCallbackHandler;

/**
 * UsernamePasswordCallbackHandler factory implementation.
 *
 * @since 1.0.0
 */
public class UsernamePasswordCallbackHandlerFactory implements PrototypeServiceFactory<CarbonCallbackHandler> {

    @Override
    public CarbonCallbackHandler getService(Bundle bundle,
                                          ServiceRegistration<CarbonCallbackHandler>
                                                  httpCallbackHandlerServiceRegistration) {
        return new UsernamePasswordCallbackHandler();
    }

    @Override
    public void ungetService(Bundle bundle,
                             ServiceRegistration<CarbonCallbackHandler> httpCallbackHandlerServiceRegistration,
                             CarbonCallbackHandler carbonCallbackHandler) {

    }
}
