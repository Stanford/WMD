# $Id$

AuthType WebAuth
WebAuthLdapAttribute displayName
WebAuthLdapAttribute suAffiliation

<?php if ($rewrite_url): ?>
RewriteEngine on
RewriteCond %{REQUEST_FILENAME} !-f
<?php print $rewrite_url; ?>
<?php endif; ?>

# Auto-generated below this line. Changes will be overwritten.
<?php if ($require_valid_user): ?>
require valid-user
<?php else: ?>
require user <?php print $users; ?>

<?php foreach($privgroups as $group): ?>
require privgroup <?php print $group; ?>

<?php endforeach; ?>
<?php endif; ?>

<?php foreach ($groups as $group): ?>
WebAuthLdapPrivgroup <?php print $group . "\n"; ?>
<?php endforeach; ?>
