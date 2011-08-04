# $Id$

AuthType WebAuth
require valid-user

WebAuthLdapAttribute displayName
WebAuthLdapAttribute suAffiliation

<?php foreach ($groups as $group): ?>

WebAuthLdapPrivgroup <?php print $group; ?>

<?php endforeach; ?>