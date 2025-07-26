# CloudAware Security Audit

This plugin adds auditing functionality to Wordpress.

## Description

This plugin adds auditing functionality to Wordpress. It does this by adding extra 
REST API endpoints. Using these endpoints it is possible to:
- see the version of core
- see whether there is an update available for core
- see what plugins are installed
- see whether these plugins have been actived
- see whether these plugins have autoupdate enabled
- see whether these plugins have updates
- see a list of vulnerabilities for these plugins
- see what themes are installed
- check if 2FA is enabled
For installations where the RESTAPI is disabled, the plugin can also push this information to an endpoint.
This will work for installations that are behind a geoblock or have no RESTAPI. To disable this, remove the
cronjob.

## Installation

Install the plugin via the Wordpress "Plugins" menu in Wordpress and then 
activate using the blue "Activate" button.

## Frequently Asked Questions

## Is it safe?
We use as little rights as possible to get the data from Wordpress.  
The API endpoint does not include any POST, PUT or DELETE methods, so it is read-only.
If you do see a problem with this plugin, please contact us:
https://cloudaware.eu/.well-known/security.txt

## Dependancies

For getting vulnerabilities of Wordpress components this plugin can use the WPVulnerability plugin 
(https://wordpress.org/plugins/wpvulnerability/). If this plugin is installed, it will be used, otherwise this plugin
will work without the information from WPVulnerabilty plugin.  
Without installing this dependancy no data is transferred to WPVulnerability. Please see https://www.wpvulnerability.com/privacy/
for more information.

## External services

In order to determine the latest version of installed software components this plugin uses the following
external services:
*GitHub*
Terms of Service: https://docs.github.com/en/site-policy/github-terms/github-terms-of-service
Privacy Statement: https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement
- Releases list from ImageMagick github repository (https://api.github.com/repos/ImageMagick/ImageMagick/releases)
- Releases list from curl github repository (https://api.github.com/repos/curl/curl/releases)
*Slider Revolution*
Terms of Service: https://www.sliderrevolution.com/terms/
Privacy Statement: https://www.sliderrevolution.com/terms/privacy/
- Changelog documentation from Slider Revolution website (https://www.sliderrevolution.com/documentation/changelog/)

Apart from the usual headers (ip-address, UserAgent) used in a GET request no other information is send to these services.
Specifically no version information is transmitted to external services.  

If you fill out an external url in the callback URL field in the settings, a Wordpress cronjob will send a POST request 
with the audit data to this URL daily.

## Changelog

= v1.0.9 =
* Code cleanup
* Add hashing of theme and plugin folders
* Add button to setting to add new user and role to system
* Cleaner initialisation, deinitialisation

= v1.0.8 =
* Added check if 2FA is enabled through Wordfence plugin

= v1.0.7 =
* Added documentation, removed creation of user

= v1.0.6 =
* Added more configuration checks

= v1.0.5 =
* Added more config checks
* Added new role for use in API (no more external plugin needed)

= v1.0.4 =
* Removed curl dependancy
* Better error handling

= v1.0.0 =
* Initial release
