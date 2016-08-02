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

package org.wso2.carbon.security.caas.user.core.sample;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;
import org.wso2.carbon.security.caas.user.core.service.RealmService;
import org.wso2.carbon.security.caas.user.core.store.IdentityStore;
import org.wso2.msf4j.Microservice;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Sample application to use identity management APIs in user core.
 */
@Component(
        name = "SampleIdentityGateway",
        service = Microservice.class,
        immediate = true
)
@Path("/identity-gateway")
public class SampleIdentityGateway implements Microservice {

    private static final org.slf4j.Logger log = LoggerFactory.getLogger(SampleIdentityGateway.class);

    @Activate
    protected void activate(BundleContext context) {
        log.info("Sample identity gateway activated.");
    }

    @Reference(
            name = "org.wso2.carbon.security.CarbonRealmServiceImpl",
            service = RealmService.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterCarbonRealm"
    )
    public void registerCarbonRealm(RealmService carbonRealmService) {
        IdentityDataHolder.getInstance().registerCarbonRealmService(carbonRealmService);
        log.info("Realm service successfully registered.");
    }

    public void unregisterCarbonRealm(RealmService carbonRealmService) {
        IdentityDataHolder.getInstance().unregisterCarbonRealmServer();
        log.info("Realm service successfully unregistered.");
    }

    @GET
    @Path("get-user/{symbol}")
    @Produces({"application/json", "text/xml"})
    public Response getUser(@PathParam("symbol") String symbol) {

        IdentityStore identityStore = IdentityDataHolder.getInstance().getCarbonRealmService().getIdentityStore();
        try {
            User user = identityStore.getUser(symbol);
            return Response.ok(user.getUserId(), MediaType.APPLICATION_JSON_TYPE).build();
        } catch (IdentityStoreException e) {
            return Response.serverError().build();
        } catch (UserNotFoundException e) {
            return Response.serverError().build();
        }
    }
}
