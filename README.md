<a href="https://www.jahia.com/">
    <img src="https://www.jahia.com/modules/jahiacom-templates/images/jahia-3x.png" alt="Jahia logo" title="Jahia" align="right" height="60" />
</a>

Spam filtering for Jahia
==========================================

This is a custom module for the Digital Factory platform
that enables automatic checking and filtering of spam content in blogs, comments, wikis, etc.

Licensing
---------
See LICENSE file

Features
--------
- Integration with the Akismet spam filtering service to detect spam inside of submitted content
- Email notification to administrators when spam is detected
- Spam is automatically filtered so that only moderators may see it
- For authenticated users, if they send spam regularly and a certain limit is reached, their
  account will be automatically locked
- For non-authenticated users, if they send spam regularly and a certain limit is reached, their
  host/IP address will be blacklisted temporarily and the administrators will be notified.
- A REST API allows administrators to view or purge the host blacklist.
- By default, if a jnt:post node is responsible for creating a jnt:topic parent node and that the 
former contains spam, both the topic and the post will be marked as spam, making it easier to purge
all the spam content by querying for the mixin.

Disclaimer
----------
This module was developed by Sergiy Shyrkov and is distributed in the hope that
it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

The status of this development is a "Prototype" and is not targeted to be deployed
and run on a production instance of Digital Factory.

Requirements
------------
Module is targeted to be deployed to Digital Factory version 7.1.0.0 or later.

Installation
------------

Simply deploy the module and then modify your jahia.properties file with the following properties:

    ######################################################################
    ### Spam filtering properties  #######################################
    ######################################################################
    # the following setting controls whether the spam lock account notifications should be sent or not
    spamMailNotificationActive=true
    # the spamMailNotificationTemplatePath point to a location inside the module where the mail template
    # (using the Velocity template language) is located. Usually you do not need to modify this unless
    # you want to copy the original template to make your own version and point to it.
    spamMailNotificationTemplatePath=/META-INF/mails/templates/accountLocked.vm
    # The spamAdministratorEmail is the destination email account that will
    # be notified when accounts are locked
    spamAdministratorEmail=info@jahia.com
    # The spamMailNotificationFrom is the sender of the locked account
    # email notifications
    spamMailNotificationFrom=forum-spam@jahia.com
    # The spamFilterHostUrlPart is used to generate absolute URLs to point to the content that contains
    # the spam. You should point this to the real server you are using.
    spamFilterHostUrlPart=http://localhost:8080

    # Once you get your API key from Akismet, you will
    # need to encrypt it to store it safely in this value in the jahia.properties file.
    # To encrypt it, go to http://localhost:8080/tools/groovyConsole.jsp and enter the following
    # command:
    #
    #     out.print(org.jahia.utils.EncryptionUtils.passwordBaseEncrypt("YOUR_API_KEY"))
    #
    #  This will print out the encrypted value you can then use.
    #
    #
    akismetEncryptedApiKey=YOUR_ENCRYPTED_API_KEY

    # The spamMaxSessionsToKill controls the maximum size of the sessions to kill hash map.
    # Normally you don't need to change this, but this is just here for information on the
    # default value.
    spamMaxSessionsToKill=20

    # For non-authenticated users, the spam filtering system will blacklist IP addresses that have
    # sent a number of spams (defaults to 3 in rules.drl). The IP blacklisting is temporary and is
    # controlled by a timeout value in milliseconds (defaults to 24h)
    spamHostBlacklistingTimeout=86400000
    # The following setting is the location of the Velocity template to format the email sent to
    # administrators when an IP is blacklisted
    spamMailHostBlacklistedNotificationTemplatePath=/META-INF/mails/templates/hostBlacklisted.vm
    # By default, when an IP is blacklisted, only *write* operations on the URLs controlled
    # by the spamBlacklistUrlMappings setting are prevented. If the following setting is set to
    # false then ALL HTTP requests to those mappings will be forbidden.
    spamAllowReadMethodsWhenBlacklisted=true
    # The following setting controls a white list of hosts/IPs that will always be allowed
    spamWhitelistedHosts=127.0.0.1,localhost
    # The following URL mappings are the patterns that will be used to filter the blacklisted
    # requests. Note that these mappings are called before URL rewriting, so make sure they
    # are properly setup.
    spamBlacklistUrlMappings=/cms/*,*.do
    
    # If this property is set, then when a node is marked as spam, it will also mark the parents
    # of the specified types ONLY if they are single parents.
    markSingleParentsOfTypes=jnt:topic

REST API
--------

A new REST API has been introduced to view/purge the blacklisting of hosts/IPs in the case
of unauthenticated users. In the source code, in src/main/bin you will find some scripts
that call the REST API to retrieve or purge the list of blacklisted hosts.

You should copy these scripts to a work location and then edit the common.sh script to
point it to your configuration and administration credentials.

Once it is configure you can simply use :

    ./getBlacklistedHosts.sh
    
to retrieve a JSON object that contains the list of blacklisted hosts.

You can use :

    ./purgeBlacklistedHosts.sh
    
to purge the list of blacklisted hosts.

If you prefer to use the REST API calls directly, these map to the following URLs : 

    GET $SERVER_HOST:$SERVER_PORT/modules/api/spamfiltering/v1/blacklisting/hosts
    Retrieves the list of blacklisted hosts
    
    DELETE $SERVER_HOST:$SERVER_PORT/modules/api/spamfiltering/v1/blacklisting/hosts
    Purges the list of blacklisted hosts
    
## Open-Source

This is an Open-Source module, you can find more details about Open-Source @ Jahia [in this repository](https://github.com/Jahia/open-source).
