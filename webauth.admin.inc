<?php
/**
 * webauth.admin.inc
 */
 
function webauth_admin_settings() {
	if (variable_get('webauth_nossl', FALSE)) {
	  return;
	}
	
	$defValue = variable_get('webauth_allow_local', 1);
	$form['webauth_allow_local'] = array(
		'#type' => 'radios',
		'#title' => t('Stanford WebAuth options'),
		'#default_value' => $defValue,
		'#options' => array(0 => t('Hide Local Drupal Accounts'), 1 => t('Allow Local Drupal Accounts')),
		'#description' => t('Hide Local Drupal Accounts will allow users to only login through Stanford WebLogin.'),
	);
	$form['webauth_link_text'] = array(
		'#type' => 'textfield',
		'#title' => t('WebLogin Link Text'),
		'#size' => 80, '#maxlength' =>255,
		'#default_value' => variable_get('webauth_link_text','SUNetID Users'),
		'#description' => t('The text which is displayed as the link to the WebLogin page for SUNetID users.')
	);
	$form['webauth_destination'] = array(
		'#type' => 'textfield',
		'#title' => t('Post-Login Destination'),
		'#size' => 80, '#maxlength' => 255,
		'#default_value' => variable_get('webauth_destination', ''),
		'#description' => t('Drupal node to which the browser redirects after successful weblogin. (Ex: \'node/add/page\' will automatically redirect user to a new content page.) If unsure, just leave blank to keep Drupal\'s default behavior.')
	);
	
	$defValue3 = variable_get('webauth_autologin', 0);
	$form['webauth_autologin'] = array(
		'#type' => 'radios',
		'#title' => t('WebAuth Auto-Login'),
		'#default_value' => $defValue3,
		'#options' => array(0 => t('Disable WebAuth Auto-Login'), 1 => t('Enable Webauth Auto-Login')),
		'#description' => t('Enable or Disable WebAuth Auto-Login feature. When enabled, option for auto-login appears on node-edit page.'),
	);

	$defValue2 = variable_get('webauth_restrict', 0);
  $form['webauth_restrict'] = array(
    '#type' => 'radios',
    '#title' => t('Node Access Restrictions'),
		'#default_value' => $defValue2,
    '#options' => array(0 => t('Disable Node Access Restrictions'), 1 => t('Enable Node Access Restrictions')),
    '#description' => t('Enable or Disable WebAuth-based node access restrictions for Drupal roles and Stanford Workgroups'),
  );

	$form['webauth_restrict_message'] = array(
		'#type' => 'textfield',
		'#title' => t('Restricted Access Message'),
		'#default_value' => variable_get('webauth_restrict_message', ''),
		'#description' => t('Message to be displayed to user when access to content is restricted.'),
	);

	$ldapDescription = 'Credential cache is needed for restricting content access based on Stanford Workgroup membership. Example: "/opt/www/apache/conf/webauth/krb5cc_ldap"<br />';
	$ldapDescription .= WORKGROUP_MSG;
	$form['webauth_ldap_cred'] = array(
		'#type' => 'textfield',
		'#title' => t('LDAP Credential Cache Location'),
		'#size' => 80, 
		'#maxlength' => 255,
		'#default_value' => variable_get('webauth_ldap_cred', NULL),
		'#description' => t($ldapDescription));

  $form['webauth_ldap_test'] = array(
    '#type' => 'fieldset',
    '#title' => t('Test LDAP Connection'),
    '#collapsible' => FALSE,
    '#collapsed' => FALSE,
    '#description' => t('Enter a SUNetID and a Stanford Workgroup in the boxes below to test LDAP connectivity.'),
  );

  $form['webauth_ldap_test']['tstLDAPuserid'] = array(
    '#type' => 'textfield',
    '#title' => 'SUNetID',
    '#default_value' => variable_get('tstLDAPuserid', NULL),
    '#size' => 20,
    '#maxlength' => 255,
  );

  $form['webauth_ldap_test']['tstLDAPgroup'] = array(
    '#type' => 'textfield',
    '#title' => 'Stanford Workgroup',
    '#default_value' => variable_get('tstLDAPgroup', NULL),
    '#size' => 20,
    '#maxlength' => 255,
  );
		
	$form['#validate'] = array('validateWebAuthAdmin');

	return system_settings_form($form);
}

function webauth_admin_groups(&$form_state) {
	if (variable_get('webauth_nossl', FALSE)) {
	  return;
	}
	$form = array();
	$groups = array();
	$table = array();
	$submitted = !empty($form_state['post']);
	
	$result = db_query("SELECT wr.warid, r.name, wr.wa_group as `group` FROM {webauth_roles} wr INNER JOIN {role} r ON wr.rid = r.rid WHERE r.rid > 2");
	while ($group = db_fetch_object($result)) {
	  $button_id = 'remove_warid_' . $group->warid;
	  $form[$button_id] = array(
	    '#name' => $button_id,
	    '#type' => 'submit',
	    '#value' => t('Remove Mapping'),
	  );
	  if (!$submitted) {
	    $row = array($group->name, $group->group, drupal_render($form[$button_id]));
	    $table[] = $row;
	  }
	}
	
	$header = array(t('Drupal Role'), t('SUNet Group'), t('Action'));
	
	$result = db_query('SELECT rid, name FROM {role}');
 	while ($role = db_fetch_object($result)) {
 	  $roles[$role->rid] = $role->name;
 	}
  
  $form['new_rid'] = array(
    '#name' => 'new_rid',
    '#type' => 'select',
    '#options' => $roles,
  );
  
  $form['new_group'] = array(
    '#name' => 'new_group',
    '#type' => 'textfield',
    '#default_value' => '',
  );
  
  $form['new_submit'] = array(
    '#name' => 'new_submit',
    '#type' => 'submit',
    '#value' => t('Add Mapping'),
  );
  
  if (!$submitted) {
    $table[] = array(drupal_render($form['new_rid']), drupal_render($form['new_group']), drupal_render($form['new_submit']));  
    $form['output'] = array(
      '#value' => theme('table', $header, $table),
    );
  }

	return $form;
}

function webauth_admin_groups_validate($form, &$form_state) {
}

function webauth_admin_groups_submit($form, &$form_state) {
  if ($form_state['clicked_button']['#value'] == t('Add Mapping')) {
    // Add mapping
    db_query("INSERT INTO {webauth_roles} (rid,wa_group) VALUES (%d,'%s')", $form_state['values']['new_rid'], $form_state['values']['new_group']);
    $role_name = db_result(db_query("SELECT name FROM role WHERE rid = %d", $form_state['values']['new_rid']));
    drupal_set_message("Added new Webauth mapping: $role_name => " . $form_state['values']['new_group']);
  }
  elseif ($form_state['clicked_button']['#value'] == t('Remove Mapping')) {
    // Remove mapping
    $warid = drupal_substr($form_state['clicked_button']['#parents'][0], 13);
    db_query("DELETE FROM {webauth_roles} WHERE warid = %d", $warid);
    drupal_set_message("Removed Webauth mapping from table. [ID: $warid]");
  }
  
  // Need to update the .htaccess file.
  webauth_write_htaccess();
}
