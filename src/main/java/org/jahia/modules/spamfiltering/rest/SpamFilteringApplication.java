package org.jahia.modules.spamfiltering.rest;

import com.fasterxml.jackson.jaxrs.json.JacksonJaxbJsonProvider;
import org.glassfish.jersey.media.multipart.MultiPartFeature;

import javax.ws.rs.core.Application;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by loom on 04.12.15.
 */
public class SpamFilteringApplication extends Application {

    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> classes = new HashSet<>();
        classes.add(SpamFilteringResource.class);
        classes.add(MultiPartFeature.class);
        classes.add(SpamFilteringAuthorizationFilter.class);
        classes.add(JacksonJaxbJsonProvider.class);
        // classes.add(LoggingFilter.class);
        return classes;
    }

}
