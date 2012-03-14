<?php
/**
 * @file
 * Administration functions for the WebAuth module
 */

function webauth_admin_settings() {

  $result = db_query('SELECT rid, name FROM {role} WHERE rid > 2');
  $roles = array();
  while ($role = db_fetch_object($result)) {
    $roles[$role->rid] = $role->name;
  }

  $form['webauth_allow_local'] = array(
    '#type' => 'radios',
    '#title' => t('Stanford WebAuth options'),
    '#default_value' => variable_get('webauth_allow_local', 1),
    '#options' => array(0 => t('Hide Local Drupal Accounts'), 1 => t('Allow Local Drupal Accounts')),
    '#description' => t('Hide Local Drupal Accounts will allow users to only log in through Stanford WebLogin.'),
  );
  $form['webauth_link_text'] = array(
    '#type' => 'textfield',
    '#title' => t('WebLogin Link Text'),
    '#size' => 80,
    '#maxlength' => 255,
    '#default_value' => variable_get('webauth_link_text', 'Login with your SUNet ID'),
    '#description' => t('The text which is displayed as the link to the WebLogin page for SUNet ID users.')
  );
  $form['webauth_destination'] = array(
    '#type' => 'textfield',
    '#title' => t('Post-Login Destination'),
    '#size' => 80, '#maxlength' => 255,
    '#default_value' => variable_get('webauth_destination', ''),
    '#description' => t('Drupal node to which the browser redirects after successful weblogin. (Ex: \'node/add/page\' will automatically redirect user to a new content page.) If unsure, just leave blank to keep Drupal\'s default behavior.')
  );

  $form['webauth_restrict_message'] = array(
    '#type' => 'textarea',
    '#title' => t('Restricted Access Message'),
    '#cols' => 80,
    '#rows' => 5,
    '#default_value' => variable_get('webauth_restrict_message', 'This content has been restricted by the author or by the site administrator.'),
    '#description' => t('Message to be displayed to user when access to content is restricted.')
  );

  return system_settings_form($form);
}

function webauth_admin_groups(&$form_state) {

  $form = array();
  $groups = array();
  $table = array();
  $submitted = !empty($form_state['post']);

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

  if (!$submitted) {
    $table[] = array(drupal_render($form['new_rid']), drupal_render($form['new_group']), drupal_render($form['new_submit']));
  }
  else {
    // Keep the UI consistent.
    $form['new_rid']['#prefix'] = '<table><tr class="odd"><td>';
    $form['new_rid']['#suffix'] = '</td><td>';
    $form['new_group']['#suffix'] = '</td><td>';
    $form['new_submit']['#suffix'] = '</td><td>';
    $form['cancel'] = array(
      '#type' => 'markup',
      '#value' => l(t('Cancel'), 'admin/settings/webauth/mappings'),
      '#suffix' => '</td></tr></table>',
    );
  }

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
  $form['output'] = array(
    '#value' => theme('table', $header, $table),
  );

  return $form;
}

function webauth_admin_groups_validate($form, &$form_state) {
  if ($form_state['clicked_button']['#value'] == t('Add Mapping')) {
    if (preg_match("/^[-_\w\d\~]+:[\w\d-_]+$/", $form_state['values']['new_group']) == 0) {
      form_set_error('new_group', t('There was an error in your group name.  Please make sure you entered it correctly.'));
    }
    if (db_result(db_query("SELECT * FROM {webauth_roles} WHERE rid = %d AND wa_group = '%s'", $form_state['values']['new_rid'], $form_state['values']['new_group']))) {
      form_set_error('new_group', t('This webauth group is already mapped to this Drupal role!'));
    }
  }
}

function webauth_admin_groups_submit($form, &$form_state) {
  if ($form_state['clicked_button']['#value'] == t('Add Mapping')) {
    // Add mapping
    db_query("INSERT INTO {webauth_roles} (rid,wa_group) VALUES (%d,'%s')", $form_state['values']['new_rid'], $form_state['values']['new_group']);
    $role_name = db_result(db_query("SELECT name FROM {role} WHERE rid = %d", $form_state['values']['new_rid']));
    drupal_set_message(check_plain("Added new WebAuth mapping: $role_name => " . $form_state['values']['new_group']));
  }
  elseif ($form_state['clicked_button']['#value'] == t('Remove Mapping')) {
    // Remove mapping
    $warid = drupal_substr($form_state['clicked_button']['#name'], 13);
    db_query("DELETE FROM {webauth_roles} WHERE warid = %d", $warid);
    drupal_set_message(check_plain("Removed WebAuth mapping from table. [ID: $warid]"));
    // Clear out any roles that were granted as a result.
    $result = db_query("SELECT * FROM {webauth_roles_history} WHERE warid = %d", $warid);
    while ($history = db_fetch_object($result)) {
      // See if there's another mapping for this role.
      if (!db_result(db_query("SELECT * FROM {webauth_roles_history} WHERE uid = %d AND rid = %d AND warid <> %d", $history->uid, $history->rid, $warid))) {
        // If not, nix the users_roles value so they lose privileges immediately.
        db_query("DELETE FROM {users_roles} WHERE uid = %d AND rid = %d", $history->uid, $history->rid);
      }
    }
    db_query("DELETE FROM {webauth_roles_history} WHERE warid = %d", $warid);
  }

  // Need to update the .htaccess file.
  webauth_write_htaccess();
}

function webauth_admin_users(&$form_state) {

  $form = array();

  $form['webauth_require_valid_user'] = array(
    '#type' => 'checkbox',
    '#title' => t('Require ANY valid user'),
    '#description' => t('Require the valid-user statement in settings. This overrides whatever users are entered below. Default is on.'),
    '#default_value' => variable_get('webauth_require_valid_user', 1),
  );

  $form['webauth_require_users'] = array(
    '#type' => 'textarea',
    '#title' => t('SUNet users permitted access'),
    '#description' => t('Enter one user per line.'),
    '#default_value' => variable_get('webauth_require_users', ''),
  );

  $form['webauth_require_privgroups'] = array(
    '#type' => 'textarea',
    '#title' => t('SUNet privgroup permitted access'),
    '#description' => t('Enter one privgroup (e.g."stanford:staff") per line.'),
    '#default_value' => variable_get('webauth_require_privgroups', ''),
  );

  $form = system_settings_form($form);

  $form['#validata'][] = 'webauth_admin_users_validate';
  $form['#submit'][] = 'webauth_admin_users_submit';

  return $form;
}

/**
 * Validate that we're getting valid input in our .htaccess file.
 */
function webauth_admin_users_validate($form, &$form_state) {
  $userlines = explode("\n", chop($form_state['values']['webauth_require_users']));
  $grouplines = explode("\n", chop($form_state['values']['webauth_require_privgroups']));

  foreach ($userlines as $line) {
    $line = chop($line);
    if ($line != '' && preg_match("/^[\w\d-_]+$/", $line) != 1) {
      form_set_error('webauth_require_users', t('!line is not a valid user format. Please enter one username per line.', array('!line' => $line)));
    }
  }
  foreach ($grouplines as $line) {
    $line = chop($line);
    if ($line != '' && preg_match("/^[-_\w\d\~]+:[\w\d-_]+$/", $line) != 1) {
      form_set_error('webauth_require_privgroups', t('!line is not a valid user format. Please enter one username per line.', array('!line' => $line)));
    }
  }

  if (trim($form_state['values']['webauth_require_users']) == '' && trim($form_state['values']['webauth_require_privgroups']) == '' && $form_state['values']['webauth_require_valid_user'] == FALSE) {
    form_set_error('webauth_require_valid_user', t('You must specify some valid means for accessing the site.'));
  }

}

function webauth_admin_users_submit($form, &$form_state) {
  // Need to update the .htaccess file.
  webauth_write_htaccess();
}

/**
 * Migrate old-style {webauth} and {webauth_force} data to {node_access}.
 *
 * This is here so it can be called from the install file or at a later date.
 */
function webauth_migrate_to_content_access() {
  // make sure content_access is loaded in case this is during an update hook
  require_once(drupal_get_path('module', 'content_access') . "/content_access.module");
  require_once(drupal_get_path('module', 'content_access') . "/content_access.admin.inc");

  $types = array(); // we will need to track node types touched so they're enabled.
  $default_role = variable_get('webauth_default_role', 0);
  // The webauth table contains specific mappings, which we should respect.
  $result = db_query("SELECT * FROM {webauth}");
  while ($webauth_access = db_fetch_object($result)) {
    $node = node_load($webauth_access->nid);
    $webauth_roles = unserialize($webauth_access->roles);

    if (trim($webauth_access->sugroups) != '') {
      $sugroups = explode(',', $webauth_access->sugroups);
      foreach ($sugroups as $sugroup) {
        $sugroup = trim($sugroup);
        $wa_mapped_role = db_fetch_object(db_query("SELECT * FROM {webauth_roles} WHERE wa_group = '%s'", $sugroup));
        if ($wa_mapped_role->rid) {
          $webauth_roles[$wa_mapped_role->rid] = $wa_mapped_role->rid;
        }
        else {
          $role_exists = (bool) db_result(db_query("SELECT COUNT(*) FROM {role} WHERE name = '%s'", $sugroup));
          if (!$role_exists) {
            db_query("INSERT INTO {role} (name) VALUES ('%s')", $sugroup);
            drupal_set_message(check_plain("Added Role $sugroup"));
          }
          $rid = db_result(db_query("SELECT rid FROM {role} WHERE name = '%s'", $sugroup));
          if ($rid) {
            db_query("INSERT INTO {webauth_roles} (rid,wa_group) VALUES (%d, '%s')", $rid, $sugroup);
            drupal_set_message(check_plain("Added Group mapping for $sugroup => $sugroup"));
            $webauth_roles[$rid] = $rid;
          }
        }
      }
    }

    $settings = array(
      'view' => array_keys($webauth_roles),
      'view_own' => array(),
      'update' => array(),
      'update_own' => array(),
      'delete' => array(),
      'delete_own' => array(),
    );
    content_access_save_per_node_settings($node, $settings);
    $types[$node->type] = 1;
  }

  // Force maps to the default role, so only proceed if we have one set.
  if ($default_role > 0) {
    $result = db_query("SELECT * FROM {webauth_force}");
    $settings = array(
      'view' => array($default_role),
      'view_own' => array(),
      'update' => array(),
      'update_own' => array(),
      'delete' => array(),
      'delete_own' => array(),
    );
    while ($webauth_force = db_fetch_object($result)) {
      $node = node_load($webauth_force->nid);
      content_access_save_per_node_settings($node, $settings);
      $types[$node->type] = 1;
    }
  }

  // Ensure that all types are set to per-node control.
  $content_access_settings = array('per_node' => $types);
  content_access_set_settings($content_access_settings);
  // Rebuild content_access settings.
  content_access_mass_update($types);
  drupal_set_message(check_plain(t("You need to rebuild the node access settings now. You can do that !link.", array('!link' => l(t('here'), 'admin/content/node-settings')))), 'error');
  node_access_needs_rebuild(TRUE);
}
