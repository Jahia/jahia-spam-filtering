<%@ taglib prefix="jcr" uri="http://www.jahia.org/tags/jcr" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ taglib prefix="template" uri="http://www.jahia.org/tags/templateLib" %>
<c:if test="${renderContext.loggedIn}">
    <jcr:nodeProperty name="jcr:lastModifiedBy" node="${currentNode}" var="author"/>
    <c:set var="canAcceptSpam" value="${jcr:hasPermission(currentNode, 'spam-filtering')}"/>
    <c:if test="${canAcceptSpam || not empty author && renderContext.user.username == author.string}">
        <div style="overflow: hidden; background :#eaeaea url(<c:url value='/gwt/resources/images/deleted-overlay.png'/>) top left; border: 1px dashed #ccc;">
            <div style="color:#f00; font-weight:bold; text-align: center;">This content was detected as a possible spam and is blocked.
            <c:if test="${canAcceptSpam}">
                <template:tokenizedForm>
                    <form action="<c:url value='${url.base}${currentNode.path}'/>" method="post" style="float:right;">
                        <input type="hidden" name="jcrRedirectTo" value="<c:url value='${url.base}${renderContext.mainResource.node.path}'/>" />
                        <input type="hidden" name="jcrNewNodeOutputFormat" value="html" />
                        <input type="hidden" name="jcrMethodToCall" value="delete" />
                        <input type="submit" class="button" value="Delete" onclick="return confirm('This will delete the conent permanently. Would you like to continue?');"/>
                    </form>
                </template:tokenizedForm>
                <template:tokenizedForm>
                    <form action="<c:url value='${url.base}${currentNode.path}'/>" method="post" style="float:right;">
                        <input type="hidden" name="jcrRedirectTo" value="<c:url value='${url.base}${renderContext.mainResource.node.path}'/>" />
                        <input type="hidden" name="jcrNewNodeOutputFormat" value="html" />
                        <input type="hidden" name="jcrMethodToCall" value="put" />
                        <input type="hidden" name="jcrRemoveMixin" value="jmix:spamFilteringSpamDetected" />
                        <input type="submit" class="button" value="Not a spam" onclick="return confirm('This will accept the content as being not spam. Would you like to continue?');"/>
                    </form>
                </template:tokenizedForm>
            </c:if>
            </div>
            ${wrappedContent}
        </div>
    </c:if>
</c:if>