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

package org.wso2.carbon.security.caas.user.core.bean;

import org.wso2.carbon.security.caas.user.core.exception.StoreException;

/**
 * Represents a action for resource.
 */
public class Action {

    public static final String DELIMITER = ":";

    private String actionNamespace;
    private String action;

    public Action(String actionString) {

        if (!actionString.contains(DELIMITER)) {
            throw new StoreException("Invalid or cannot find the delimiter.");
        }

        actionNamespace = actionString.substring(0, actionString.indexOf(DELIMITER));
        action = actionString.substring(actionString.indexOf(DELIMITER) + 1, actionString.length());
    }

    public Action(String actionNamespace, String action) {
        this.actionNamespace = actionNamespace;
        this.action = action;
    }

    public String getActionNamespace() {
        return actionNamespace;
    }

    public String getAction() {
        return action;
    }

    public String getActionString() {
        return actionNamespace + DELIMITER + action;
    }
}
