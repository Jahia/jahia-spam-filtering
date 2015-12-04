package org.jahia.modules.spamfiltering;

import javax.xml.bind.annotation.XmlRootElement;
import java.util.Date;

/**
 * Metadata about a host that is sending spam
 */
@XmlRootElement
public class HostStats {

    private String remoteHost;
    private Date lastPost;
    private int spamCount = 0;
    private int blacklistingCount = 0;
    private boolean blacklisted = false;
    private long blacklistingTimeout = 0;

    public HostStats() {
    }

    public HostStats(String remoteHost, Date lastPost, int spamCount, boolean blacklisted, long blacklistingTimeout) {
        this.remoteHost = remoteHost;
        this.lastPost = lastPost;
        this.spamCount = spamCount;
        this.blacklisted = blacklisted;
        this.blacklistingTimeout = blacklistingTimeout;
    }

    public String getRemoteHost() {
        return remoteHost;
    }

    public Date getLastPost() {
        return lastPost;
    }

    public void setLastPost(Date lastPost) {
        this.lastPost = lastPost;
    }

    public int getSpamCount() {
        return spamCount;
    }

    public void setSpamCount(int spamCount) {
        this.spamCount = spamCount;
    }

    public int getBlacklistingCount() {
        return blacklistingCount;
    }

    public void setBlacklistingCount(int blacklistingCount) {
        this.blacklistingCount = blacklistingCount;
    }

    public boolean isBlacklisted() {
        return blacklisted;
    }

    public void setBlacklisted(boolean blacklisted) {
        this.blacklisted = blacklisted;
    }

    public long getBlacklistingTimeout() {
        return blacklistingTimeout;
    }

    public void setBlacklistingTimeout(long blacklistingTimeout) {
        this.blacklistingTimeout = blacklistingTimeout;
    }

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("HostStats{");
        sb.append("remoteHost='").append(remoteHost).append('\'');
        sb.append(", lastPost=").append(lastPost);
        sb.append(", spamCount=").append(spamCount);
        sb.append(", blacklistingCount=").append(blacklistingCount);
        sb.append(", blacklisted=").append(blacklisted);
        sb.append(", blacklistingTimeout=").append(blacklistingTimeout);
        sb.append('}');
        return sb.toString();
    }
}
