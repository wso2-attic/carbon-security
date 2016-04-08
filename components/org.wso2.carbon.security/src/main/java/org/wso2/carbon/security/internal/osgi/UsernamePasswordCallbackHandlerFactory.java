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

package org.wso2.carbon.security.internal.osgi;

import org.osgi.framework.Bundle;
import org.osgi.framework.PrototypeServiceFactory;
import org.osgi.framework.ServiceRegistration;
import org.wso2.carbon.security.jaas.HTTPCallbackHandler;
import org.wso2.carbon.security.jaas.handler.UsernamePasswordCallbackHandler;

/**
 * UsernamePasswordCallbackHandler factory implementation
 */
public class UsernamePasswordCallbackHandlerFactory implements PrototypeServiceFactory<HTTPCallbackHandler> {

    @Override
    public HTTPCallbackHandler getService(Bundle bundle,
                                          ServiceRegistration<HTTPCallbackHandler>
                                                  httpCallbackHandlerServiceRegistration) {
        return new UsernamePasswordCallbackHandler();
    }

    @Override
    public void ungetService(Bundle bundle,
                             ServiceRegistration<HTTPCallbackHandler> httpCallbackHandlerServiceRegistration,
                             HTTPCallbackHandler httpCallbackHandler) {

    }
}
