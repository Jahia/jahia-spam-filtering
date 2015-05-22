/**
 * ==========================================================================================
 * =                        DIGITAL FACTORY v7.0 - Community Distribution                   =
 * ==========================================================================================
 *
 *     Rooted in Open Source CMS, Jahia's Digital Industrialization paradigm is about
 *     streamlining Enterprise digital projects across channels to truly control
 *     time-to-market and TCO, project after project.
 *     Putting an end to "the Tunnel effect", the Jahia Studio enables IT and
 *     marketing teams to collaboratively and iteratively build cutting-edge
 *     online business solutions.
 *     These, in turn, are securely and easily deployed as modules and apps,
 *     reusable across any digital projects, thanks to the Jahia Private App Store Software.
 *     Each solution provided by Jahia stems from this overarching vision:
 *     Digital Factory, Workspace Factory, Portal Factory and eCommerce Factory.
 *     Founded in 2002 and headquartered in Geneva, Switzerland,
 *     Jahia Solutions Group has its North American headquarters in Washington DC,
 *     with offices in Chicago, Toronto and throughout Europe.
 *     Jahia counts hundreds of global brands and governmental organizations
 *     among its loyal customers, in more than 20 countries across the globe.
 *
 *     For more information, please visit http://www.jahia.com
 *
 * JAHIA'S DUAL LICENSING - IMPORTANT INFORMATION
 * ============================================
 *
 *     Copyright (C) 2002-2014 Jahia Solutions Group SA. All rights reserved.
 *
 *     THIS FILE IS AVAILABLE UNDER TWO DIFFERENT LICENSES:
 *     1/GPL OR 2/JSEL
 *
 *     1/ GPL
 *     ==========================================================
 *
 *     IF YOU DECIDE TO CHOSE THE GPL LICENSE, YOU MUST COMPLY WITH THE FOLLOWING TERMS:
 *
 *     "This program is free software; you can redistribute it and/or
 *     modify it under the terms of the GNU General Public License
 *     as published by the Free Software Foundation; either version 2
 *     of the License, or (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program; if not, write to the Free Software
 *     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *     As a special exception to the terms and conditions of version 2.0 of
 *     the GPL (or any later version), you may redistribute this Program in connection
 *     with Free/Libre and Open Source Software ("FLOSS") applications as described
 *     in Jahia's FLOSS exception. You should have received a copy of the text
 *     describing the FLOSS exception, and it is also available here:
 *     http://www.jahia.com/license"
 *
 *     2/ JSEL - Commercial and Supported Versions of the program
 *     ==========================================================
 *
 *     IF YOU DECIDE TO CHOOSE THE JSEL LICENSE, YOU MUST COMPLY WITH THE FOLLOWING TERMS:
 *
 *     Alternatively, commercial and supported versions of the program - also known as
 *     Enterprise Distributions - must be used in accordance with the terms and conditions
 *     contained in a separate written agreement between you and Jahia Solutions Group SA.
 *
 *     If you are unsure which license is appropriate for your use,
 *     please contact the sales department at sales@jahia.com.
 */
package org.jahia.modules.spamfiltering.rules;

import java.util.*;

import javax.jcr.PropertyIterator;
import javax.jcr.PropertyType;
import javax.jcr.RepositoryException;
import javax.jcr.Value;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.apache.velocity.tools.generic.DateTool;
import org.apache.velocity.tools.generic.EscapeTool;
import org.drools.core.spi.KnowledgeHelper;
import org.jahia.bin.Jahia;
import org.jahia.modules.spamfiltering.SpamFilteringService;
import org.jahia.modules.spamfiltering.filters.SpamFilter;
import org.jahia.modules.spamfiltering.listeners.SpamServletRequestListener;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRPropertyWrapper;
import org.jahia.services.content.nodetypes.ExtendedPropertyDefinition;
import org.jahia.services.content.rules.AddedNodeFact;
import org.jahia.services.content.rules.User;
import org.jahia.services.mail.MailService;
import org.jahia.services.usermanager.JahiaUser;
import org.jahia.settings.SettingsBean;
import org.jahia.utils.LanguageCodeConverters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Service class for checking content and applying spam filtering.
 * 
 * @author Sergiy Shyrkov
 */
public class SpamFilteringRuleService {

    private static Logger logger = LoggerFactory.getLogger(SpamFilteringRuleService.class);

    private static final String SPAM_DETECTED_MIXIN = "jmix:spamFilteringSpamDetected";

    private static final String SPAM_SESSIONS_PROPERTY_NAME = "org.jahia.modules.spamfiltering.spamSessions";

    private SpamFilteringService spamFilteringService;

    private boolean sendSpamNotificationEmails = true;
    private MailService mailService;
    private SpamFilter spamFilter;

    private String templatePath;
    private String emailFrom;
    private String emailTo;
    private String spamFilterHostUrlPart;

    /**
     * Verifies the content of the node with anti-spam service and applies spam filtering (by assigning a special mixin).
     * 
     * @param nodeFact
     *            the node which content should be checked
     * @param maxSpamCount the number of maximum spams tolerated before the user is locked and his session is killed.
     * @param drools
     *            the rule engine helper class
     * @throws RepositoryException
     *             in case of an error
     */
    public void checkForSpam(AddedNodeFact nodeFact, Integer maxSpamCount, KnowledgeHelper drools)
            throws RepositoryException {
        if (logger.isDebugEnabled()) {
            logger.debug("Checking content of the node {} for spam", nodeFact.getPath());
        }

        try {
            User user = (User) drools.getWorkingMemory().getGlobal("user");

            HttpServletRequest httpServletRequest = spamFilter.getHttpServletRequest();

            if (httpServletRequest == null) {
                // we didn't manage to get the request from our own filter, try to access it through Spring MVC's
                // framework
                try {
                    RequestAttributes requestAttributes = RequestContextHolder.currentRequestAttributes();
                    if (requestAttributes != null && requestAttributes instanceof ServletRequestAttributes) {
                        ServletRequestAttributes servletRequestAttributes = (ServletRequestAttributes) requestAttributes;
                        httpServletRequest = servletRequestAttributes.getRequest();
                    }
                } catch (IllegalStateException ise) {
                    logger.warn("Couldn't retrieve request from Spring MVC controller : " + ise.getMessage());
                }
                if (httpServletRequest == null ) {
                    // we could reach this stage if the incoming request is coming from a REST API call or another
                    // direct call to OSGi's HttpService.
                    if (SpamServletRequestListener.getServletRequestEvent() != null) {
                        ServletRequest servletRequest = SpamServletRequestListener.getServletRequestEvent().getServletRequest();
                        if (servletRequest instanceof HttpServletRequest) {
                            httpServletRequest = (HttpServletRequest) servletRequest;
                        }
                    }
                }
            }

            boolean isSpam = false;
            JCRNodeWrapper node = nodeFact.getNode();
            String text = getTextContent(node);
            if (StringUtils.isNotEmpty(text)) {
                isSpam = spamFilteringService.isSpam(text, node, httpServletRequest);
            }

            if (isSpam) {
                if (!node.isNodeType(SPAM_DETECTED_MIXIN)) {
                    // is detected as spam -> add mixin
                    node.getSession().checkout(node);
                    node.addMixin(SPAM_DETECTED_MIXIN);
                }
                if (maxSpamCount != null && httpServletRequest != null) {
                    HttpSession httpSession = httpServletRequest.getSession(false);
                    JahiaUser jahiaUser = user.getJahiaUser();
                    if (httpSession != null && !"guest".equals(jahiaUser.getName()) && !jahiaUser.isRoot()) {
                        String spamSessionsValue = jahiaUser.getProperty(SPAM_SESSIONS_PROPERTY_NAME);
                        List<String> spamSessions = new ArrayList<String>();
                        if (spamSessionsValue != null) {
                            spamSessions.addAll(Arrays.asList(spamSessionsValue.split(",")));
                        }

                        spamSessions.add(httpSession.getId());

                        if (spamSessions.size() >= maxSpamCount) {
                            logger.info("Maximum number of spam count reached (" + maxSpamCount + "), locking user account and killing session...");
                            logger.info("Marking session " + httpSession.getId() + " as invalid and will be killed on next access.");
                            spamFilter.addSessionToKill(httpSession.getId());
                            // add code to lock account
                            logger.info("Locking account " + jahiaUser + "...");
                            jahiaUser.setProperty("j:accountLocked", "true");
                            if (sendSpamNotificationEmails) {
                                logger.info("Sending account lock notification to administrator...");
                                sendAccountLockNotification(node, jahiaUser, httpServletRequest);
                            }
                            // we clear the session list to avoid it growing to big
                            spamSessions.clear();
                        } else {
                            logger.info("User " + jahiaUser + " has sent " + spamSessions.size() + " spam so far.");
                        }

                        if (spamSessions.size() > 0) {
                            jahiaUser.setProperty(SPAM_SESSIONS_PROPERTY_NAME, StringUtils.join(spamSessions, ","));
                        } else {
                            jahiaUser.removeProperty(SPAM_SESSIONS_PROPERTY_NAME);
                        }

                    }
                }
            } else if (node.isNodeType(SPAM_DETECTED_MIXIN)) {
                // no longer spam -> remove mixin
                node.getSession().checkout(node);
                node.removeMixin(SPAM_DETECTED_MIXIN);
            }
            logger.info("Content of the node {} is{} detected as spam", node.getPath(),
                    !isSpam ? " not" : "");
        } catch (Exception e) {
            logger.warn("Unable to check the content of the node " + nodeFact.getPath()
                    + " for spam. Cause: " + e.getMessage(), e);
        }
    }

    private void sendAccountLockNotification(JCRNodeWrapper node, JahiaUser jahiaUser, HttpServletRequest httpServletRequest) throws RepositoryException {
        // Prepare mail to be sent :
        String administratorEmail = emailTo == null ? mailService.getSettings().getTo() : emailTo;

        Locale defaultLocale = null;
        if (node.getExistingLocales() != null &&
                node.getExistingLocales().size() > 0) {
            defaultLocale = node.getExistingLocales().get(0);
        }
        if (defaultLocale == null) {
            defaultLocale = LanguageCodeConverters.languageCodeToLocale(SettingsBean.getInstance().getDefaultLanguageCode());
        }

        Map<String, Object> bindings = new HashMap<String, Object>();
        bindings.put("spamNode", node.getParent());
        bindings.put("spamNewNode", node);
        bindings.put("ParentSpamNode", node.getParent().getParent());
        bindings.put("submitter", jahiaUser);
        if (httpServletRequest != null) {
            bindings.put("httpServletRequest", httpServletRequest);
        }
        bindings.put("date", new DateTool());
        bindings.put("esc", new EscapeTool());
        bindings.put("submissionDate", Calendar.getInstance());
        bindings.put("spamURL", spamFilterHostUrlPart + Jahia.getContextPath() + node.getUrl());

        try {
            bindings.put("locale", defaultLocale);
            mailService.sendMessageWithTemplate(templatePath, bindings, administratorEmail, emailFrom, "", "", defaultLocale, "Jahia Spam Filtering");
            logger.info("Account "+jahiaUser+" locked notification sent by e-mail to " + administratorEmail + " using locale " + defaultLocale);
        } catch (Exception e) {
            logger.error("Couldn't sent spam account lock email notification: ", e);
        }
    }


    private String getTextContent(JCRNodeWrapper node) throws RepositoryException {
        StringBuilder text = new StringBuilder();
        for (PropertyIterator iterator = node.getProperties(); iterator.hasNext();) {
            JCRPropertyWrapper prop = (JCRPropertyWrapper) iterator.nextProperty();
            ExtendedPropertyDefinition def = (ExtendedPropertyDefinition) prop.getDefinition();

            if (prop.getType() == PropertyType.STRING && !def.isHidden() && !def.isProtected()) {
                if (prop.isMultiple()) {
                    for (Value jcrValue : prop.getValues()) {
                        String val = jcrValue.getString();
                        if (StringUtils.isNotEmpty(val)) {
                            if (text.length() > 0) {
                                text.append("\n");
                            }
                            text.append(val);
                        }
                    }
                } else {
                    String val = prop.getString();
                    if (StringUtils.isNotEmpty(val)) {
                        if (text.length() > 0) {
                            text.append("\n");
                        }
                        text.append(val);
                    }
                }
            }
        }

        return text.toString();
    }

    public void setSpamFilteringService(SpamFilteringService spamFilteringService) {
        this.spamFilteringService = spamFilteringService;
    }

    public void setMailService(MailService mailService) {
        this.mailService = mailService;
    }

    public void setSendSpamNotificationEmails(boolean sendSpamNotificationEmails) {
        this.sendSpamNotificationEmails = sendSpamNotificationEmails;
    }

    public void setTemplatePath(String templatePath) {
        this.templatePath = templatePath;
    }

    public void setEmailFrom(String emailFrom) {
        this.emailFrom = emailFrom;
    }

    public void setEmailTo(String emailTo) {
        this.emailTo = emailTo;
    }

    public void setSpamFilterHostUrlPart(String spamFilterHostUrlPart) {
        this.spamFilterHostUrlPart = spamFilterHostUrlPart;
    }

    public void setSpamFilter(SpamFilter spamFilter) {
        this.spamFilter = spamFilter;
    }
}