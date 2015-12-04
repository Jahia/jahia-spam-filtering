package org.jahia.modules.spamfiltering.filters;

import org.jahia.bin.filters.AbstractServletFilter;
import org.jahia.modules.spamfiltering.HostStats;
import org.jahia.modules.spamfiltering.rules.SpamFilteringRuleService;
import org.slf4j.Logger;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;

/**
 * A servlet filter needed since we cannot use a render filter on actions
 */
public class SpamServletFilter extends AbstractServletFilter {

    private static Logger logger = org.slf4j.LoggerFactory.getLogger(SpamServletFilter.class);

    private SpamFilteringRuleService spamFilteringRuleService;

    public void setSpamFilteringRuleService(SpamFilteringRuleService spamFilteringRuleService) {
        this.spamFilteringRuleService = spamFilteringRuleService;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        Map<String, HostStats> blacklistedHosts = spamFilteringRuleService.getBlacklistedHosts();
        boolean okToContinue = true;
        if (blacklistedHosts != null) {
            String remoteHost = servletRequest.getRemoteHost();
            if (remoteHost == null) {
                remoteHost = servletRequest.getRemoteAddr();
            }
            if (blacklistedHosts.containsKey(remoteHost)) {
                HostStats hostStats = blacklistedHosts.get(remoteHost);
                if (hostStats.isBlacklisted()) {
                    long now = System.currentTimeMillis();
                    if (hostStats.getBlacklistingTimeout() == 0 || hostStats.getBlacklistingTimeout() > now && servletRequest instanceof HttpServletRequest) {
                        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
                        // host is blacklisted, let's refuse serving the request
                        String httpMethod = httpServletRequest.getMethod().toLowerCase();
                        if (spamFilteringRuleService.isAllowReadingWhenBlacklisted() && (httpMethod.equals("get") || httpMethod.equals("head") || httpMethod.equals("options"))) {
                            // even if the host is blacklisted, we still allow these three HTTP methods.
                            logger.info("Host {} is blacklisted but read-only HTTP methods (get/head/options) are still allowed", hostStats);
                        } else {
                            httpServletRequest.getSession().invalidate();
                            okToContinue = false;
                        }
                    } else if (hostStats.getBlacklistingTimeout() != 0 && hostStats.getBlacklistingTimeout() <= now) {
                        // black listing has expired, let's remove it.
                        hostStats.setBlacklisted(false);
                        hostStats.setBlacklistingTimeout(0);
                        spamFilteringRuleService.getBlacklistedHosts().put(remoteHost, hostStats);
                    }
                }
            }
        }
        if (okToContinue) {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }

    @Override
    public void destroy() {

    }
}
