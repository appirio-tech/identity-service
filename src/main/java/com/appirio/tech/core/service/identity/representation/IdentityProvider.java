package com.appirio.tech.core.service.identity.representation;

import com.appirio.tech.core.api.v3.model.AbstractIdResource;

/**
 * Created by ramakrishnapemmaraju on 12/7/15.
 */
public class IdentityProvider extends AbstractIdResource {

    private String name;
    private String type;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }
}
