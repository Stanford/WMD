$Id: README 1807 2010-03-18 16:53:04Z ksharp $

WMD - WebAuth Module for Drupal 6.x  - version 2.55

A module that integrates Stanford WebLogin into Drupal 6.x. Comments and suggestions are welcome.

LICENSE:

This Educational Community License (the "License") applies to any original work of authorship (the "Original Work") whose owner (the "Licensor") has placed the following notice immediately following the copyright notice for the Original Work:
    Copyright (c) 2007-2009  The Board of Trustees of Leland Stanford Junior University

Licensed under the Educational Community License version 1.0
This Original Work, including software, source code, documents, or other related items, is being provided by the copyright holder subject to the terms of the Educational Community License. By obtaining, using and/or copying this Original Work, you agree that you have read, understand, and will comply with the following terms and conditions of the Educational Community License:

Permission to use, copy, modify, merge, publish, distribute, and sublicense this Original Work and its documentation, with or without modification, for any purpose, and without fee or royalty to the copyright holder is hereby granted, provided that you include the following on ALL copies of the Original Work or portions thereof, including modifications or derivatives, that you make:

    * The full text of the Educational Community License in a location viewable to users of the redistributed or derivative work.
    * Any pre-existing intellectual property disclaimers, notices, or terms and conditions.
    * Notice of any changes or modifications to the Original Work, including the date the changes were made.
    * Any modifications of the Original Work must be distributed in such a manner as to avoid any confusion with the Original Work of the copyright holders.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
The name and trademarks of copyright holder may NOT be used in advertising or publicity pertaining to the Original or Derivative Works without specific, written prior permission. Title to copyright in the Original Work and any associated documentation will at all times remain with the copyright holders.


CONTENTS:

I.	BACKGROUND: Goals and Problems
II.	IMPLEMENTATION
III.	INSTALLATION
IV.	UPGRADES
V.	CRON
VI.	WHAT'S NEW


I. BACKGROUND:

Goals:

	1. Allow anonymous access to some Drupal content while restricting other content in the same site with WebAuth. (For example, create a web site whose content is open, but read-only, to the public while editable only to those with valid SUNetIDs, or a site where some conent is public, but other content is likewise restricted.

	2. Allow for login using either internal Drupal accounts or external WebAuth'ed accounts.

	3. Implement as a Drupal module without touching core code.

	4. Created for the Academic Computing web site project, but general enough to be useful throughout the Stanford Drupal community.

	5. Provide means by which read-access to content may be restricted granularly by Drupal role or by membership in a Stanford WorkGroup.

Problems:

	1. Drupal does not organize content in directories. Instead, all Drupal pages are created dynamically by its index.php script using URL query parameters to specify which content nodes to display. So, there's no way to use .htaccess files to restrict some content while leaving the rest open.

	2. Drupal supports "external" login accounts, which are distinguished from regular accounts by the presence of "@server" in the user id. Unfortunately, Drupal's external login hook assumes the user will use Drupal's login page to enter userid and password, which will then be authenticated through some back-channel function call. This does not readily lend itself to use of our standard WebLogin page.

	3. Drupal overrides PHP's session-handling with its own logic, so it is harder to share session data between Drupal and other PHP scripts.

	4. Unless the Drupal administrator sets the PHP cookie lifetime to zero, Drupal maintains the login from the previous browser session (its default is approximately 23 days). The user information is loaded from the stored session without explicitly going through the user_load routines.

	5. Drupal core allows read-access restrictions to content by role only at the site level. This means all or nothing access to all Drupal content by role membership. We'd like to restrict access to specific content by role (while leaving other content available) and also allow for access restrictions by membership in Stanford Workgroups. This last requires that the web server running Drupal be properly credentialed to do an LDAP compare operation on the user's group memberships. (More on this below in INSTALLATION.)

II. IMPLEMENTATION

1. Server Requirements

	1a. Drupal 6.0 or greater, installed on an Apache server which includes mod_webauth. (NOTE: THIS VERSION DOES NOT WORK WITH DRUPAL 5.x)

	1b. Apache's PHP module is configured with OpenSSL enabled.

	1c. In order to restrict content by Stanford Workgroup, the server must be properly credentialed to do an LDAP Compare operation on the LDAP workgroup database.


2. The module's installation script sets up a webauth-protected directory under the Drupal installation's base dirctory. This directory contains the following files:

	2a. .htaccess - the default loaded requires any valid SUNetID user and requests the user's display name and Stanford affiliation from WebAuth. 

	2b. wa_base.inc - this contains the base directory of the Drupal installation. It is used as an include to the other scripts.

	2c. wa_login.php - when a WebLogin is requested, Drupal's login process will redirect the user's browser to this script via the Stanford WebLogin page. This script then loads Drupal's session handler (using the Drupal session cookie from the browser) and writes to it the user's WebAuth display name, email address, and affiliation, a hash of the webauth_at credential, and the expiration time of the credential. The browser is then redirected back to Drupal's login process.

	2d. wa_check.php - Once the user is redirected back to Drupal's login process, this script is accessed directly by Drupal via socket connection using the webauth_at cookie from the browser. The script passes back information about the user and the credential, which Drupal uses to ensure that the user information in it's session table is correct. The login process then completes.

	2e. wa_session.inc - contains code for WMD's session handler.

	2f. .pkey - contains an RSA private key

3. The Drupal WebAuth module itself consists of 5 files: webauth.info, webauth.install, webauth.js (which includes javascript run at the browser), webauth.module (the latter containing the bulk of the integration logic), and wa_session.inc (which ocontains code for Drupal's session handler and is the same file as is stored in the webauth directory described above).

4. The webauth module's administration form allows the administrator to allow or disallow local Drupal accounts.
	
	4a. If local accounts are allowed, both the Drupal login block and login page are modified to include a link for WebAuth login in addition to the internal account userid and password fields. The link takes the user to the wa_login page described above. The text of the link may be modified by the administrator in the webauth administration form.

	4b. If local accounts are not allowed, then the userid and password fields are removed from the Drupal login block, and the WebLogin link is added. Requests for the Drupal login page (query string includes q=user/login) are automatically redirected to the wa_login page, unless the query string also includes destination=admin. (This allows the Drupal administrator to login with his or her local account.)


5. The 'webauth_init' hook in webauth.module gets called for every page request. It does the following:

	5a. Determine if user is a Stanford user by the presence of "@stanford.edu" at the end of the Drupal userid. If we have a Stanford user, and the request is not secure, then redirect the browser to the same request using https.

	5b. If the page request query string includes q=user/login and our Drupal session indicates we are back from wa_login and we have a webauth_at cookie, then do a secure socket call to wa_check to ensure our session data is correct, and complete the user login.

	5c. If the page request query string includes q=user/login, but the session indicates that we are *not* back from wa_login, the destination page is not admin, and we do not allow local logins, redirect the browser to wa_login, otherwise allow Drupal to display its own login page (with a WebLogin link added).

	5d. For any other page request for a Stanford user, check that the hash of the webauth_at cookie matches that stored in our Drupal session and that the webauth credential hasn't expired. If okay, proceed with the page request, otherwise force a logout of the user.

	5e. If none of the above is true (the user is anonymous or a local user), process the page request as usual.

6. When Drupal logs in the external user for the first time, it creates an entry in its user table. This module updates that record so that the user's "roles" are "SUNetID User" and "authenticated user" (the administrator can then use Drupal roles to restrict content and features). It also sets the password in the Drupal user table to a random value so that the Stanford user must login through WebAuth.

7. Content authors may specify access restrictions on the content node's entry page. The author may either select Drupal roles from available check-boxes, or enter the name of one or more Stanford workgroups. Authors of 'book' pages may specify on a book's top-most page that all child pages will inherit its content restrictions. Any user with the appropriate authority  may also set default restrictions for each content type. Authors with administrative credentials may select content from the "Administer Content" page and reset their restrictions to their node-type's default.

III. INSTALLATION

	1. This implementation requires Drupal 5.x running on a WebAuth'd Apache server. (This implementatiion does not run on Drupal 6.x)..

	2. Untar webauth.tar into <drupal-base>/modules or <drupal-base>/sites/all/modules. Make sure file ownerships and permissions match your other Drupal files.

	3. Log into Drupal as administrator. Go to Administer/Site Building/Modules. WebAuth should appear at the bottom of the page. Click to enable, then click "Save configuration." 

	4. Enabling the module will create a "SUNetID User" role with "access content" permission. You may modify its access permissions as you like.

	5. Enabling the module also creates 'webauth' and 'webauth_log' directories under <drupal-base> directory. Make sure their ownership and permissions are set correctly.

	6. The '<drupal-base>/webauth' directory contains the login scripts and an .htaccess file restricting it to "AuthType WebAuth" 
and  "require valid-user". Change this however you like to allow different WebAuth subsets.
	
	7. Default behavior modifies both the Drupal login page and the Drupal login block to include a "To Login with SUNetID, Click Here" link.
	
	8. Go to Administer/Site Configuration/WebAuth Settings to change the text of the WebLogin link and to set the module to hide login for internal Drupal users. This forces all users to login through WebLogin. (An exception is for Drupal Administrators, who can log in by specifying '?q=user/login&destination=admin' in the URL.) The administrator can also set a destination page to which Drupal will navigate after a successful login.

	9. In order to do access restrictions via Stanford workgroup, you must include tha file path of an appropriate credential cache. You may test the cache my specifying a userid and workgroup..Getting your web server credentialed to check Stanford Workgroup membership through LDAP requires that you get written permission (via email) from the various content-owners and then submit those permissions in a request for "WebAuth General Access Permissions at: http://www.stanford.edu/services/directory/access/request.html. A list of data owners can be found at: https://www.stanford.edu/dept/as/mais/integration/howto/permission.html.

IV. UPGRADES
	
	A. UPGRADING WITHIN DRUPAL 5.x FROM ANY WMD 1.x TO ANY OTHER WMD 1.x OR WITHIN DRUPAL 6.x FROM ANY WMD 2.x TO ANY OTHER WMD 2.x UP TO AND INCLUDING v2.42
		1. Disable Webauth module from the admin/build/modules page.
		2. Uninstall Webauth module from the admin/build/modules/uninstall page.
		3. Delete webauth directory and contents from Drupal sites/all/modules directory.
		4. Copy and un-tar new version into sites/all/modules directory
		5. Enable Webauth module from the admin/build/modules page.

	B. UPGRADING FROM DRUPAL 5.x TO DRUPAL 6.x AND PLANNING TO USE WMD v2.42 OR EARLIER (NOT RECOMMENDED)
		1. Disable Webauth module from the admin/build/modules page.
		2. Uninstall Webauth module from the admin/build/modules/uninstall page.
		3. Delete webauth directory and contents from the Drupal sites/all/modules directory.
		4. Upgrade Drupal site from 5.x to 6.x per Drupal instructions.
		5. Copy and un-tar new WMD 2.x into the sites/all/modules directory.
		6. Enable Webauth module from the admin/build/modules page.

	C. UPGRADING FROM DRUPAL 5.x to DRUPAL 6.x AND WMD v2.5 OR LATER
		1. Follow Drupal's instructions for upgrading from 5.x to 6.x but do not yet run update.php script.
		2. Delete webauth directory and contents from the Drupal sites/all/modules directory.
		3. Copy and un-tar new WMD version (2.5 or later) to sites/all/modules directory.
		4. Run Drupal update.php script. 

V. CRON

	WMD now implements Drupal's HOOK_CRON API call. This means that when Drupal's cron.php script is run (either manually, through an OS crontab entry, or using a Drupal module such as poormanscron), all WMD sessions older than 1 day will be deleted from the database.

VI. WHAT'S NEW

	V2.0
	        1. Functionally equivalent to WMD v1.5 but works with Drupal 6.x. (This version does NOT work with Drupal 5.x. Use v1.5 for that.)
        	2. No longer fixes core user.module "bug" since new authentication model renders it no longer a "bug".

	V2.1	Unreleased development version.

	V2.2
	        1. Security updates (handling of redirect headers, creation of cookies when running behind proxy, hiding session info from login url, and url-encoding of forwarded url parameters
        	2. The content-access-restriction feature is now disabled by default. It can be enabled at the admin/settings/webauth page.
	        3. The restricted-content message is now configurable at admin/settings/webauth

	V2.3	Bug fix for restricted access in book pages.

	V2.42	1. A new feature where nodes may be set to auto-login through WebAuth when accessed by an anonymous user
		2. A bug fix which caused an error message when WMD installed with PHP versions older than 5.2.0

	V2.5	1. WMD now implements its own session handler, bypassing Drupal's version of the PHP session handler. This is in response to problems caused by caching in Drupal versions since 6.10.
		2. WMD now correctly instructs browsers not to cache or store any web pages created for an authenticated SUNet user. This is also in response to caching problems.
		3. Fixes a bug where the post-login URL following WebAuth login was sometimes incorrect. The following algorithm is now used:
			a. if the post-login destination is specified in the URL as destination=admin, go to the drupal admin page
			b. else, if the login is in response to an auto-login node, go to that node
			c. else, if a default webauth post-login destination is set, go to that destination
			d. else, if the 'q' parameter is set in the URL to anything but 'user/login', go to that destination
			e. else, go to destination 'node' and let Drupal decide where to go (including default site post-login destination).
		4. WMD now implements its database tables using the Drupal Schema API, allowing Drupal to store metadata about the tables.
		5. The WMD installer script now responds to the Drupal update.php script, allowing the site administrator to simply copy the new version into the modules directory and run update
		6. The WMD installer should now no longer produce file system error messages when being installed on AFS.
		7. WMD now implements hook_cron to remove session data from the database that is over 1 day old.
		8. Information in README regarding Drupal version upgrades and WMD.

	V2.51	1. Fixed a bug in post-login destination handling where post-login COOKIE not being updated with each new page.

	V2.52	1. Changed step 3.e in v2.5 to "else, go to destination ''" instead of destination='node' in case some other module changes the front page.
		2. Previously, if wmd detected that the current session was invalid (because of missing webauth_at cookie or expired cookie) it would call drupal function
		   user_logout() which forced return to front page, even if another node was requested via hyperlink. This has been corrected so the equivalent of user_logout() 
		   is now called without forcing a return to the front page.
		3. Auto Webauth Login and Content Access Restrictons field sets are now collapsed by default on content editing pages when those features are enabled and when the page
		   is either for new content or for editiing content where those fields are unchecked.

	V2.53	1. Check PHP version before setting cookies; PHP versions older than 5.2.0 can not set the httponly parameter.
		2. Fixed cookie_domain bug in deleting post-login destination cookie.
		3. Added capability to override post-login destination cookie with wa_dest url parameter.
		4. Created webauth_login_url hook to aid in creating custom login links.

    V2.54   1. Fixed bug where nodes with webauth auto-login where, after being updated, were causing the search modules implementation of hook_cron to fail when run anonymously.
        2. Fixed interaction between webauth auto-login and content access restriction to follow more restrictive path. (That is, if auto-login is set, user will still be automatically
           redirected to WebLogin, but content will still be restricted if the node is restricted from view for SUNetID role.
    V2.55  Fix bug in content access restrictions for multiple workgroups which would a page refresh for each specified workgroup. Bug found and fixed by Marco Wise.

Ken Sharp
Systems Software Developer
Student Computing / Academic Computing
Stanford University
mailto:ksharp@stanford.edu
March 18, 2010

