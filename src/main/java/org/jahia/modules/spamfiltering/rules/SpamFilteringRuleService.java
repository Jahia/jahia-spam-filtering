/**
 * This file is part of Jahia, next-generation open source CMS:
 * Jahia's next-generation, open source CMS stems from a widely acknowledged vision
 * of enterprise application convergence - web, search, document, social and portal -
 * unified by the simplicity of web content management.
 *
 * For more information, please visit http://www.jahia.com.
 *
 * Copyright (C) 2002-2011 Jahia Solutions Group SA. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * As a special exception to the terms and conditions of version 2.0 of
 * the GPL (or any later version), you may redistribute this Program in connection
 * with Free/Libre and Open Source Software ("FLOSS") applications as described
 * in Jahia's FLOSS exception. You should have received a copy of the text
 * describing the FLOSS exception, and it is also available here:
 * http://www.jahia.com/license
 *
 * Commercial and Supported Versions of the program (dual licensing):
 * alternatively, commercial and supported versions of the program may be used
 * in accordance with the terms and conditions contained in a separate
 * written agreement between you and Jahia Solutions Group SA.
 *
 * If you are unsure which license is appropriate for your use,
 * please contact the sales department at sales@jahia.com.
 */

package org.jahia.modules.spamfiltering.rules;

import java.util.HashMap;
import java.util.Map;

import javax.jcr.PathNotFoundException;
import javax.jcr.PropertyIterator;
import javax.jcr.PropertyType;
import javax.jcr.RepositoryException;
import javax.jcr.Value;
import javax.jcr.ValueFormatException;

import org.apache.commons.lang.StringUtils;
import org.drools.spi.KnowledgeHelper;
import org.jahia.modules.spamfiltering.SpamFilteringService;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRPropertyWrapper;
import org.jahia.services.content.nodetypes.ExtendedPropertyDefinition;
import org.jahia.services.content.rules.AddedNodeFact;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service class for checking content and applying spam filtering.
 * 
 * @author Sergiy Shyrkov
 */
public class SpamFilteringRuleService {

    private static Logger logger = LoggerFactory.getLogger(SpamFilteringRuleService.class);

    private static final String SPAM_DETECTED_MIXIN = "jmix:spamFilteringSpamDetected";

    private SpamFilteringService spamFilteringService;

    /**
     * Verifies the content of the node with anti-spam service and applies spam filtering (by assigning a special mixin).
     * 
     * @param nodeFact
     *            the node which content should be checked
     * @param drools
     *            the rule engine helper class
     * @throws RepositoryException
     *             in case of an error
     */
    public void checkForSpam(AddedNodeFact nodeFact, KnowledgeHelper drools)
            throws RepositoryException {
        if (logger.isDebugEnabled()) {
            logger.debug("Checking content of the node {} for spam", nodeFact.getPath());
        }

        try {
            boolean isSpam = false;
            JCRNodeWrapper node = nodeFact.getNode();
            String text = getTextContent(node);
            if (StringUtils.isNotEmpty(text)) {
                isSpam = spamFilteringService.isSpam(text, getOptions(node));
            }

            if (node.isNodeType(SPAM_DETECTED_MIXIN)) {
                if (!isSpam) {
                    // no longer spam -> remove mixin
                    node.getSession().checkout(node);
                    node.removeMixin(SPAM_DETECTED_MIXIN);
                }
            } else {
                if (isSpam) {
                    // is detected as spam -> add mixin
                    node.getSession().checkout(node);
                    node.addMixin(SPAM_DETECTED_MIXIN);
                }
            }
            logger.info("Content of the node {} is{} detected as spam", node.getPath(),
                    !isSpam ? " not" : "");
        } catch (Exception e) {
            logger.warn("Unable to check the content of the node " + nodeFact.getPath()
                    + " for spam. Cause: " + e.getMessage(), e);
        }
    }

    private Map<String, String> getOptions(JCRNodeWrapper node) throws ValueFormatException, PathNotFoundException, RepositoryException {
        Map<String, String> options = new HashMap<String, String>(1);
        options.put("author", node.getSession().getUser().getUsername());
        
        return options;
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

}