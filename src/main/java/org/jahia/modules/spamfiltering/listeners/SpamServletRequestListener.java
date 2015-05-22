package org.jahia.modules.spamfiltering.listeners;

import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;

/**
 * Created by loom on 22.05.15.
 */
public class SpamServletRequestListener implements ServletRequestListener {

    private static ThreadLocal<ServletRequestEvent> servletRequestEventThreadLocal = new ThreadLocal<ServletRequestEvent>();

    public static ServletRequestEvent getServletRequestEvent() {
        return servletRequestEventThreadLocal.get();
    }

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {
        servletRequestEventThreadLocal.remove();
    }

    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        servletRequestEventThreadLocal.set(sre);
    }
}
