Spam filtering for Jahia xCM
==========================================

This is a custom module for the Jahia xCM platform
that enables automatic checking and filtering of spam content in blogs, comments, wikis, etc.

Licensing
---------
This module is free software; you can redistribute it and/or 
modify it under the terms of the GNU General Public License 
as published by the Free Software Foundation; either version 2 
of the License, or (at your option) any later version

Disclaimer
----------
This module was developed by Sergiy Shyrkov and is distributed in the hope that
it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

The status of this development is a "Prototype" and is not targeted to be deployed
and run on a production instance of Jahia xCM.

Requirements
------------
Module is targeted to be deployed to Jahia xCM version 6.6.0.0 or later.

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