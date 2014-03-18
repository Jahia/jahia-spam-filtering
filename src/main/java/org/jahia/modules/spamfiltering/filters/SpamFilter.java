package org.jahia.modules.spamfiltering.filters;

import org.jahia.services.render.RenderContext;
import org.jahia.services.render.Resource;
import org.jahia.services.render.filter.AbstractFilter;
import org.jahia.services.render.filter.RenderChain;
import org.slf4j.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;

/**
 * Spam rendering filter used to kill sessions immediately once they have been flagged
 */
public class SpamFilter extends AbstractFilter {

    private static Logger logger = org.slf4j.LoggerFactory.getLogger(SpamFilter.class);

    public ConcurrentLinkedQueue<String> sessionsToKill = new ConcurrentLinkedQueue<String>();
    public ThreadLocal<HttpServletRequest> httpServletRequestThreadLocal = new ThreadLocal<HttpServletRequest>();

    private int maxSessionsToKill = 20;

    public void setMaxSessionsToKill(int maxSessionsToKill) {
        this.maxSessionsToKill = maxSessionsToKill;
    }

    public void addSessionToKill(String sessionId) {
        if (!sessionsToKill.contains(sessionId)) {
            sessionsToKill.add(sessionId);
            while (sessionsToKill.size() > maxSessionsToKill) {
                // prevent queue from growing indefinitely by removing the oldest elements
                String removedSessionId = sessionsToKill.poll();
                logger.info("Removing session " + removedSessionId + " from sessions to kill list to avoid it growing too big.");
            }
        }
    }

    public void removeSessionToKill(String sessionId) {
        sessionsToKill.remove(sessionId);
    }

    @Override
    public String prepare(RenderContext renderContext, Resource resource, RenderChain chain) throws Exception {
        String s =  super.prepare(renderContext, resource, chain);
        httpServletRequestThreadLocal.set(renderContext.getRequest());
        HttpSession httpSession = renderContext.getRequest().getSession(false);
        if (httpSession != null) {
            if (sessionsToKill.contains(httpSession.getId())) {
                logger.info("Killing session " + httpSession.getId() + " containing user " + renderContext.getUser() + " from IP " + renderContext.getRequest().getRemoteAddr());
                httpSession.invalidate();
                sessionsToKill.remove(httpSession.getId());
            }
        }
        return s;
    }

    @Override
    public String execute(String previousOut, RenderContext renderContext, Resource resource, RenderChain chain) throws Exception {
        String s = super.execute(previousOut, renderContext, resource, chain);
        return s;
    }

    @Override
    public void finalize(RenderContext renderContext, Resource resource, RenderChain renderChain) {
        httpServletRequestThreadLocal.remove();
        super.finalize(renderContext, resource, renderChain);
    }

    public HttpServletRequest getHttpServletRequest() {
        return httpServletRequestThreadLocal.get();
    }
}
