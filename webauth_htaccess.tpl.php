# $Id$

AuthType WebAuth
WebAuthLdapAttribute displayName
WebAuthLdapAttribute suAffiliation

RewriteEngine on
<?php print $rewrite_url; ?>

# Auto-generated below this line. Changes will be overwritten.
<?php if ($require_valid_user): ?>
  require valid-user
<?php else: ?>
  require user <?php print $users; ?> 
<?php endif; ?>

<?php foreach ($groups as $group): ?>
  WebAuthLdapPrivgroup <?php print $group . "\n"; ?>
<?php endforeach; ?>
