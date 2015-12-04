Spam filtering for Digital Factory
==========================================

This is a custom module for the Digital Factory platform
that enables automatic checking and filtering of spam content in blogs, comments, wikis, etc.

Licensing
---------
See LICENSE file

Disclaimer
----------
This module was developed by Sergiy Shyrkov and is distributed in the hope that
it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

The status of this development is a "Prototype" and is not targeted to be deployed
and run on a production instance of Digital Factory.

Requirements
------------
Module is targeted to be deployed to Digital Factory version 7.0.0.0 or later.

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

spamHostBlacklistingTimeout=86400000
spamMailHostBlacklistedNotificationTemplatePath=/META-INF/mails/templates/hostBlacklisted.vm
spamAllowReadMethodsWhenBlacklisted=true
spamWhitelistedHosts=127.0.0.1,localhost
spamBlacklistUrlMappings=/cms/*,*.do