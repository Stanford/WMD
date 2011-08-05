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
  
	return system_settings_form($form);
}

function webauth_admin_groups(&$form_state) {
	if (variable_get('webauth_nossl', FALSE)) {
	  return;
	}
	$form = array();
	$groups = array();
	$table = array();
	
	$result = db_query("SELECT wr.warid, r.name, wr.wa_group as `group` FROM {webauth_roles} wr INNER JOIN {role} r ON wr.rid = r.rid WHERE r.rid > 2");
	while ($group = db_fetch_object($result)) {
	  $button_id = 'remove_warid_' . $group->warid;
	  $form[$button_id] = array(
	    '#name' => $button_id,
	    '#type' => 'submit',
	    '#value' => t('Remove Mapping'),
	  );
	  $row = array($group->name, $group->group, drupal_render($form[$button_id]));
	  $table[] = $row;
	}
	
	$header = array(t('Drupal Role'), t('SUNet Group'), t('Action'));
	
	$result = db_query('SELECT rid, name FROM {role} WHERE rid > 2');
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
  
  $table[] = array(drupal_render($form['new_rid']), drupal_render($form['new_group']), drupal_render($form['new_submit']));  
  $form['output'] = array(
    '#value' => theme('table', $header, $table),
  );

	return $form;
}

function webauth_admin_groups_validate($form, &$form_state) {
  $result = preg_match('/~?[\w_-]+:[\w_/-]+/', $form_state['values']['new_group']);
  print_r($result);die();
  if (count($result) <= 1) {
    //form_set_error('new_group', t('There was an error in your group name.  Please make sure you entered it correctly.'));
  }
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
