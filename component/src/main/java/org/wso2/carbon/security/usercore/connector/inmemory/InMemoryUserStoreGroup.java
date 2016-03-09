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

package org.wso2.carbon.security.usercore.connector.inmemory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * InMemoryUserStoreGroup
 */
public class InMemoryUserStoreGroup {

    private String groupID;
    private Map<String, String> groupAttributes = new HashMap<>();
    private List<String> users;

    public Map<String, String> getGroupAttributes() {
        return groupAttributes;
    }

    public void setGroupAttributes(Map<String, String> groupAttributes) {
        this.groupAttributes = groupAttributes;
    }

    public String addGroupAttribute(String attributeName, String value) {
        return groupAttributes.put(attributeName, value);
    }

    public void removeGroupAttribute(String attributeName) {
        groupAttributes.remove(attributeName);
    }

    public String getGroupID() {
        return groupID;
    }

    public void setGroupID(String groupID) {
        this.groupID = groupID;
    }

    public List<String> getUsers() {
        return users;
    }

    public void setUsers(List<String> users) {
        this.users = users;
    }

}
