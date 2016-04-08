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

package org.wso2.carbon.security.usercore.sample;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.security.usercore.bean.Group;
import org.wso2.carbon.security.usercore.bean.User;
import org.wso2.carbon.security.usercore.exception.IdentityStoreException;
import org.wso2.carbon.security.usercore.service.RealmService;
import org.wso2.carbon.security.usercore.store.IdentityStore;
import org.wso2.msf4j.Microservice;

import java.util.List;
import java.util.Map;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Sample application to use identity management APIs in user core.
 */
@Component(
        name = "org.wso2.carbon.security.usercore.sample.SampleIdentityGateway",
        service = Microservice.class,
        immediate = true
)
@Path("/identity-gateway")
public class SampleIdentityGateway implements Microservice {

    @Activate
    public void activate(BundleContext context) {
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
    }

    public void unregisterCarbonRealm(RealmService carbonRealmService) {
    }

    @POST
    @Path("add-user")
    @Consumes("application/json")
    public Response addGroup(Map data) {

        String groupName = (String) data.get("groupname");
        List<String> users = (List) data.get("users");

        IdentityStore identityStore = IdentityDataHolder.getInstance().getCarbonRealmService().getIdentityStore();
        try {
            Group group = identityStore.addGroup(groupName, users);
            return Response.ok(group).build();
        } catch (IdentityStoreException e) {
            return Response.serverError().build();
        }
    }

    @POST
    @Path("add-user")
    @Consumes("application/json")
    public Response addUser(Map data) {

        String username = (String) data.get("username");
        String password = (String) data.get("password");

        Map<String, String> claims = (Map) data.get("claims");
        List<String> groups = (List) data.get("groups");

        IdentityStore identityStore = IdentityDataHolder.getInstance().getCarbonRealmService().getIdentityStore();
        try {
            User user = identityStore.addUser(username, claims, password.toCharArray(), groups);
            return Response.ok(user, MediaType.APPLICATION_JSON_TYPE).build();
        } catch (IdentityStoreException e) {
            return Response.serverError().build();
        }
    }

    @GET
    @Path("get-user/{symbol}")
    @Produces({"application/json", "text/xml"})
    public Response getUser(@PathParam("symbol") String symbol) {

        IdentityStore identityStore = IdentityDataHolder.getInstance().getCarbonRealmService().getIdentityStore();
        try {
            User user = identityStore.getUser(symbol);
            return Response.ok(user, MediaType.APPLICATION_JSON_TYPE).build();
        } catch (IdentityStoreException e) {
            return Response.serverError().build();
        }
    }
}
