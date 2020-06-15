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
 *     Copyright (C) 2002-2020 Jahia Solutions Group SA. All rights reserved.
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
package org.jahia.modules.spamfiltering.akismet;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import org.apache.jackrabbit.util.ISO8601;
import org.jahia.modules.spamfiltering.SpamFilteringService;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.notification.HttpClientService;
import org.jahia.settings.SettingsBean;

import javax.jcr.PathNotFoundException;
import javax.jcr.RepositoryException;
import javax.jcr.ValueFormatException;
import javax.servlet.http.HttpServletRequest;

/**
 * Utility class for communicating with the external akismet.com REST service for spam checking.
 * 
 * @author Sergiy Shyrkov
 */
public class AkismetService implements SpamFilteringService {

    private static final Map<String, String> DEF_PARAMS;

    static {
        DEF_PARAMS = new HashMap<String, String>();
        DEF_PARAMS.put("blog", "http://localhost:8080");
        DEF_PARAMS.put("user_ip", "127.0.0.1");
        DEF_PARAMS.put("comment_type", "comment");
        DEF_PARAMS.put("user_agent",
                "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:8.0) Gecko/20100101 Firefox/8.0");
    }

    private static final String SPAM_FORCE_MARKER = "viagra-test-123";

    private String apiKey;

    private HttpClientService httpClientService;

    public boolean isSpam(String content, JCRNodeWrapper node, HttpServletRequest httpServletRequest) throws Exception {
        return isSpam(content, getOptions(node, content, httpServletRequest));
    }

    private boolean isSpam(String content, Map<String, String> options) throws Exception {
        Map<String, String> parameters = new HashMap<String, String>(DEF_PARAMS);
        if (options != null && !options.isEmpty()) {
            for (Map.Entry<String,String> option : options.entrySet()) {
                if (option.getKey() != null && option.getValue() != null) {
                    parameters.put(option.getKey(), option.getValue());
                }
            }
        }
        parameters.put("comment_content", content);

        Map<String, String> headers = new HashMap<String, String>(1);
        headers.put("Content-Type", "application/x-www-form-urlencoded; charset="
                + SettingsBean.getInstance().getCharacterEncoding());

        String result = httpClientService.executePost("http://" + apiKey
                + ".rest.akismet.com/1.1/comment-check", parameters, headers);

        if (result == null || "invalid".equals(result)) {
            throw new IllegalArgumentException("Unable to perform content check for spam");
        }

        return "true".equals(result);
    }

    private Map<String, String> getOptions(JCRNodeWrapper node, String content, HttpServletRequest httpServletRequest) throws ValueFormatException, PathNotFoundException, RepositoryException {
        Map<String, String> options = new HashMap<String, String>(1);
        options.put("author", node.getSession().getUser().getUsername());
        if (httpServletRequest != null) {
            options.put("blog", node.getResolveSite().getAbsoluteUrl(httpServletRequest));
            options.put("user_ip", httpServletRequest.getRemoteAddr());
            options.put("user_agent", httpServletRequest.getHeader("User-Agent"));
            options.put("referrer", httpServletRequest.getHeader("Referer"));
        }
        // options.put("permalink", "");
        options.put("comment_type", "comment");
        if (content.contains(SPAM_FORCE_MARKER)) {
            options.put("comment_author", SPAM_FORCE_MARKER);
        } else {
            options.put("comment_author", node.getSession().getUser().getUsername());
        }
        // Email address submitted with the comment
        if (node.getSession().getUser().getProperty("email") != null) {
            options.put("comment_author_email", node.getSession().getUser().getProperty("email"));
        }
        if (node.getSession().getUser().getProperty("url") != null) {
            options.put("comment_author_url", node.getSession().getUser().getProperty("url"));
        }
        // The UTC timestamp of the creation of the comment, in ISO 8601 format. May be omitted if the comment is sent to the API at the time it is created.
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(node.getCreationDateAsDate());
        options.put("comment_date_gmt", ISO8601.format(calendar));
        calendar.setTime(node.getLastModifiedAsDate());
        options.put("comment_post_modified_gmt", ISO8601.format(calendar));
        options.put("blog_lang", node.getSession().getLocale().toString());
        options.put("blog_charset", SettingsBean.getInstance().getCharacterEncoding());

        return options;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public void setHttpClientService(HttpClientService httpClientService) {
        this.httpClientService = httpClientService;
    }

}
