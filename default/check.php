<?php
// $Id: wa_check.inc 811 2008-06-18 23:13:46Z ksharp $

/**
 * @file
 * Returns webauth information to the Drupal webauth module
 * to verify that a webauth_at cookie is valid.
 */
	
foreach ($_SERVER as $key => $value) {
	if (strtoupper(substr($key, 0, 8)) === 'WEBAUTH_') {
		$key2 = strtolower(substr($key, 8));
		header('wa_' . $key2 . ': ' . $value);
	}
}
header('wa_remote_user: ' . $_SERVER['REMOTE_USER']);

print '<html><head><title>wa_check</title></head>';
print '<body>';
print '</body></html>';
