<?php
/**
 * @file WebAuthSession
 *
 * WMD's session handler.
 *
 */
class WebAuthSession {

  /**
   * Session data.
   */
  protected $data;

  /**
   * Auth URL
   */
  protected $authUrl;

  /**
   * Headers from WebAuth.
   */
  protected $headers = array();

  /**
   * WebAuth AT Cookie.
   */
  protected $atCookie;

  /**
   * Return URL.
   */
  protected $returnUrl;

  /**
   * Logged in status.
   */
  protected $loggedIn;

  /**
   * Initialize the object.
   */
  public function __construct() {
    // Initialize the object and populate the headers.
    $this->__init();

    // Check for WebAuth AT Cookie.
    $this->getAtCookie();

    // If we don't have an at_cookie, we have not authenticated yet.
    if (empty($this->atCookie)) {
      $this->loggedIn = FALSE;
    }
    else {
      $this->loggedIn = TRUE;
    }
  }

  private function __init() {
    // Set our authentication redirect URL.
    $this->makeAuthUrl();

    // Get AT cookie.
    $this->getAtCookie();

    // Get our session data.
    $this->loadSessionData();
  }

  public function getSessionData($key = NULL) {
    if (!empty($key)) {
      return $this->data[$key];
    }
    else {
      return $this->data;
    }
  }

  public function getReturnUrl($clear = FALSE) {
    if ($clear) {
      $this->returnUrl = $_SESSION['wa_return_url'];
      unset($_SESSION['wa_return_url']);
    }
    return $this->returnUrl;
  }

  // Save the token expiration date in the session object so that it can be checked
  // later without having to call check.php
  public function writeSessionData() {
    if (isset($_SERVER['HTTPS'])) {
      $_SESSION['wa_session_data']['wa_token_expiration'] = $this->data['wa_token_expiration'];
    }
  }

  public function loadSessionData() {
    if (isset($_SESSION['wa_session_data'])) {
      $this->data = $_SESSION['wa_session_data'];
    }
    elseif ($this->isLoggedIn())  {
      $this->getHeaderData();
      foreach ($this->headers as $k => $v) {
        // Check for WA_LDAPPRIVGROUP.
        if (drupal_substr($k, 0, 16) == 'wa_ldapprivgroup') {
          $this->data['ldap_groups'][$v] = $v;
        }
        else {
          $this->data[$k] = $v;
        }
      }
      if ($this->isLoggedIn()) {
        $this->writeSessionData();
      }
    }
  }

  public function isValidSession() {
    if (isset($this->atCookie)) {
      if (empty($this->data)) {
        $this->loadSessionData();
      }
      if (!empty($this->data)) {
        if (time() <= $this->data['wa_token_expiration'] && $this->isLoggedIn()) {
          return TRUE;
        }
      }
    }
    return FALSE;
  }

  public function isLoggedIn() {
    return (bool) $this->loggedIn;
  }

  public function getLdapGroups() {
    return $this->data['ldap_groups'] ? $this->data['ldap_groups'] : array();
  }

  public function getAtCookie() {
    if (isset($_COOKIE['webauth_at'])) {
      $this->atCookie = $_COOKIE['webauth_at'];
    }
  }

  public function getWeblogin($redirect = NULL) {
    if (!empty($redirect)) {
      $this->makeAuthUrl($redirect);
    }
    header("Location: " . $this->authUrl);
    exit();
  }

  public function makeReturnUrl($url = NULL) {
    // if there is a post-login destination set, that's the destination
    // otherwise, it's the regular drupal destination
    $post_login_destination = trim(variable_get('webauth_destination', ''));

    if (!empty($post_login_destination)) {
      $this->returnUrl  = $post_login_destination;
    }
    else {
      $destination = drupal_get_destination();
      $this->returnUrl  = substr($destination, 12);
    }
  }

  public function makeAuthUrl($redirect = NULL) {
    // Create auth URL.
    $this->authUrl = $this->getLoginUrl($redirect);
  }

  public function getLoginUrl($url = NULL) {
    // Make sure we create a return url before we make a login url.
    $this->makeReturnUrl($url);

    // This is a fix for non-clean urls.  Need to provide a link to the full
    // path so that we hit the webauth dir. That dir will redirect to proper
    // non-clean path after authentication via webauth.
    if (!variable_get('clean_url', FALSE)) {
      $return = 'https://' . $_SERVER['SERVER_NAME'] . base_path() . variable_get('webauth_path', conf_path() . '/webauth')
                . '/login';
      if (isset($this->returnUrl)) {
        $return .= '?destination=' . $this->returnUrl;
      }
    }
    else {
      $return = url(variable_get('webauth_path', conf_path() . '/webauth') . '/login',
                    array('absolute' => TRUE, 'query' => array('destination' => $this->returnUrl)));
    }
    return $return;
  }

  public function getHeaderData() {
    // Read and parse the header data provided by requesting check.php.
    // This is the source of all webauth data for the system.
    $url = parse_url(url(variable_get('webauth_path', conf_path() . '/webauth') . '/check.php', array('absolute' => TRUE)));
    if (variable_get('clean_url', FALSE) == FALSE) {
      $url['path'] = base_path() . variable_get('webauth_path', conf_path() . '/webauth') . '/check.php';
    }
    $sock = fsockopen('ssl://' . $url['host'], 443, $errno, $errstr, 10);
    if (!$sock) {
      drupal_set_message(check_plain('Unable to authenticate because of socket error: ' . $errstr), 'error');
      return FALSE;
    }
    fwrite($sock, "GET " . $url['path'] . " HTTP/1.1\r\n");
    fwrite($sock, "Host: " . $url['host'] . "\r\n");
    fwrite($sock, "Connection: close\r\n");
    fwrite($sock, "Cookie: webauth_at=" . urlencode($this->atCookie) . "\r\n");
    fwrite($sock, "Accept: */*\r\n");
    fwrite($sock, "\r\n");
    fwrite($sock, "\r\n");

    $return = '';
    while (!feof($sock)) {
      $return .= fread($sock, 8192);
    }
    fclose($sock);

    $return_data = array();
    list($return_data['headers'],
         $return_data['body']) = explode("\r\n\r\n", $return);

    $headers = explode("\r\n", $return_data['headers']);

    if (strpos($headers[0], 'HTTP/1.1 404 Not Found') !== FALSE) {
      watchdog('webauth', 'Connecting to check.php failed, check.php not found at %path".', array('%path' => 'https://' . $url['host'] . $url['path']), WATCHDOG_WARNING);
      drupal_set_message(t('Error: Login failed. Please contact the administrator of this website.'),'error');
      $this->loggedIn = FALSE;
      drupal_goto('<front>');
      return;
    }
    $status = (bool) (strpos($headers[0], 'HTTP/1.1 200 OK') !== FALSE);
    if ($status) {
      $this->loggedIn = TRUE;
      foreach ($headers as $header) {
        list($hName, $hVal) = explode(': ', $header, 2);
        $hName = trim($hName);
        $hVal = trim($hVal);
        if (substr($hName, 0, 3) == 'wa_') {
          $this->headers[$hName] = $hVal;
        }
      }
    }
    else {
      $this->loggedIn = FALSE;
    }
  }
}
