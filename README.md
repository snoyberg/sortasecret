# SortaSecret

*A really simple Mailhide replacement*

Purpose: you want to put someone's email address on a website, but use Recaptcha to ensure that it's a real human and not a bot reading it. SortaSecret provides a service where a third party application:

* Asks sortasecret.com to encrypt the email address
* Embeds the encrypted version of the email address on the web page
* Includes some Javascript
* The Javascript asks Recaptcha to verify that the user isn't a bot, provides that token to sortasecret.com with the encrypted payload, and gets back the email address
