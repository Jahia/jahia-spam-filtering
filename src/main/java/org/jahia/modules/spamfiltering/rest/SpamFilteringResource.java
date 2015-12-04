package org.jahia.modules.spamfiltering.rest;

import org.jahia.modules.spamfiltering.HostStats;
import org.jahia.modules.spamfiltering.rules.SpamFilteringRuleService;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.Map;

/**
 * Created by loom on 04.12.15.
 */
@Path("/api/spamfiltering/v1")
public class SpamFilteringResource {

    private SpamFilteringRuleService spamFilteringRuleService;

    public SpamFilteringRuleService getSpamFilteringRuleService() {
        if (spamFilteringRuleService == null) {
            spamFilteringRuleService = SpamFilteringRuleService.getInstance();
        }
        return spamFilteringRuleService;
    }

    public void setSpamFilteringRuleService(SpamFilteringRuleService spamFilteringRuleService) {
        this.spamFilteringRuleService = spamFilteringRuleService;
    }

    @GET
    @Path("/version")
    @Produces(MediaType.APPLICATION_JSON)
    public String getInfo() {
        return "2.0.1-SNAPSHOT";
    }

    @DELETE
    @Path("/blacklisting/hosts")
    public void clearBlacklistedHosts() {
        getSpamFilteringRuleService().getBlacklistedHosts().clear();
    }

    @GET
    @Path("/blacklisting/hosts")
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, HostStats> getBlacklistedHosts() {
        return getSpamFilteringRuleService().getBlacklistedHosts();
    }

}
