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

package org.wso2.carbon.security.caas.user.core.store;

import org.wso2.carbon.security.caas.user.core.bean.Attribute;
import org.wso2.carbon.security.caas.user.core.bean.Group;
import org.wso2.carbon.security.caas.user.core.bean.User;
import org.wso2.carbon.security.caas.user.core.claim.Claim;
import org.wso2.carbon.security.caas.user.core.config.IdentityStoreConnectorConfig;
import org.wso2.carbon.security.caas.user.core.domain.DomainManager;
import org.wso2.carbon.security.caas.user.core.exception.GroupNotFoundException;
import org.wso2.carbon.security.caas.user.core.exception.IdentityStoreException;
import org.wso2.carbon.security.caas.user.core.exception.UserNotFoundException;

import java.util.List;
import java.util.Map;
import javax.security.auth.callback.Callback;

/**
 * Represents a virtual identity store to abstract the underlying stores.
 *
 * @since 1.0.0
 */

public interface IdentityStore {

    /**
     * Initialize the identity store instance.
     *
     * @param domainManager            DomainManager instance for which is shared by the identity store
     *                                 and the credentials store.
     * @param identityConnectorConfigs Connector configs related to the identity store.
     * @throws IdentityStoreException Identity Store Exception.
     */
    void init(DomainManager domainManager, Map<String, IdentityStoreConnectorConfig> identityConnectorConfigs)
            throws IdentityStoreException;


    void getUser(String userId) throws IdentityStoreException, UserNotFoundException;
    void getUser(String userId, String domain) throws IdentityStoreException, UserNotFoundException;

    void getUser(Claim claim) throws IdentityStoreException, UserNotFoundException;
    void getUser(Claim claim, String domain) throws IdentityStoreException, UserNotFoundException;

    List<User> listUsers(Claim claim, int offset, int length) throws IdentityStoreException;
    List<User> listUsers(Claim claim, String filterPattern, int offset, int length) throws IdentityStoreException;

    Group getGroup(String groupId) throws IdentityStoreException, GroupNotFoundException;
    Group getGroup(Claim claim) throws IdentityStoreException, GroupNotFoundException;

    List<Group> listGroups(String groupId) throws IdentityStoreException;
    List<Group> listGroups(Claim claim, String filterPattern, int offset, int length) throws IdentityStoreException;

    List<Group> getGroupsOfUser(String userId) throws IdentityStoreException;
    List<User> getUsersOfGroup(String groupId) throws IdentityStoreException;

    boolean isUserInGroup(String userId, String groupId) throws IdentityStoreException;


}
