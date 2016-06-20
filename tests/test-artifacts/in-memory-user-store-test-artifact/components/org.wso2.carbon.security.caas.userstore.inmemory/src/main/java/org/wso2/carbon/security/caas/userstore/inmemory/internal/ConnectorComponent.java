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

package org.wso2.carbon.security.caas.userstore.inmemory.internal;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.caas.user.core.store.connector.AuthorizationStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.store.connector.CredentialStoreConnectorFactory;
import org.wso2.carbon.security.caas.user.core.store.connector.IdentityStoreConnectorFactory;
import org.wso2.carbon.security.caas.userstore.inmemory.InMemoryAuthorizationStoreConnectorFactory;
import org.wso2.carbon.security.caas.userstore.inmemory.InMemoryCredentialStoreConnectorFactory;
import org.wso2.carbon.security.caas.userstore.inmemory.InMemoryIdentityStoreConnectorFactory;

import java.util.Dictionary;
import java.util.Hashtable;

/**
* OSGi component for carbon security connectors.
* @since 1.0.0
*/
@Component(
        name = "org.wso2.carbon.security.caas.connector.inmemory.ConnectorComponent",
        immediate = true
)
public class ConnectorComponent {

    private static final Logger log = LoggerFactory.getLogger(ConnectorComponent.class);

    /**
     * Register user store connectors as OSGi services.
     * @param bundleContext @see BundleContext
     */
    @Activate
    public void registerCarbonSecurityConnectors(BundleContext bundleContext) {

        Dictionary<String, String> connectorProperties = new Hashtable<>();

        connectorProperties.put("connector-type", "InMemoryIdentityStore");
        bundleContext.registerService(IdentityStoreConnectorFactory.class, new InMemoryIdentityStoreConnectorFactory(),
                                      connectorProperties);

        connectorProperties = new Hashtable<>();
        connectorProperties.put("connector-type", "InMemoryAuthorizationStore");
        bundleContext.registerService(AuthorizationStoreConnectorFactory.class,
                                      new InMemoryAuthorizationStoreConnectorFactory(), connectorProperties);

        connectorProperties = new Hashtable<>();
        connectorProperties.put("connector-type", "InMemoryCredentialStore");
        bundleContext.registerService(CredentialStoreConnectorFactory.class,
                                      new InMemoryCredentialStoreConnectorFactory(), connectorProperties);

        if (log.isDebugEnabled()) {
            log.debug("InMemory user store connectors registered as services successfully.");
        }
    }
}
