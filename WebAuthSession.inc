<?php
// $Id$
/**
 * @file WebAuthSession
 *
 * WMD's session handler.
 *
 */
class WebAuthSession {
  
  /**
   * Session ID.
   */
  protected $sid;
  
  /**
   * Session name.
   */
  protected $name;
  
  /**
   * Session data.
   */
  protected $data;
  
  /**
   * Cookie domain.
   */
  protected $domain;
  
  /**
   * Cookie sent.
   */
  protected $cookieSent = FALSE;
  
  /**
   * Error data.
   */
  protected $error;
  
  /**
   * Auth URL
   */
  protected $authUrl;
  
  /**
   * Headers from WebAuth.
   */
  protected $headers = array();
  
  /**
   * Raw return data from check.php.
   */
  protected $returnData = array();
  
  /**
   * Webauth AT Cookie.
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
    global $cookie_domain;
    
    $this->domain = $cookie_domain;
    
    $this->name = session_name();
    
    $this->sid = session_id();
    
    // Set our authentication redirect URL.
    $this->makeAuthUrl();
    
    // Get AT cookie.
    $this->getAtCookie();
    
    // Get our session data.
    $this->loadSessionData();
  }
  
  /**
   * Public function to write cookie to user.
   * @param string $name
   * @param string $value
   * @param string $expire
   * @param string $path
   * @param string $domain
   * @param bool $secure
   * @param bool $httpOnly
   */
  public function writeCookie($name, $value) {
  	// see if we've already made this cookie request
  	static $cookieRequests = array();
  	
  	if (isset($cookieRequests[$name]) && $cookieRequests[$name] === $value) {
  		return; // request already made
  	} 
  	else {
  		$cookieRequests[$name] = $value; // store it for testing
  	}

  	// write a cookie to the browser - check for PHP version to see whether to include $httpOnly value
  	if (version_compare(PHP_VERSION,'5.2.0') === -1) {
  		setcookie($name, $value, 0, '/', $this->domain, TRUE);
  	} 
  	else {
  		setcookie($name, $value, 0, '/', $this->domain, TRUE, TRUE);
  	}
  }
  
  public function getSessionName() {
    return $this->name;
  }
  
  public function getSessionId() {
    return $this->sid;
  }
  
  public function getSessionData($key = NULL) {
    if (!empty($key)) {
      return $this->data[$key];
    }
    else {
      return $this->data;
    }
  }
  
  public function getReturnUrl() {
    return $this->returnUrl;
  }

  public function writeSessionData() {
    if (isset($_SERVER['HTTPS'])) {
      $_SESSION['wa_session_data'] = $this->data;
    }
  }

  public function sessionStart() {
  }
  
  public function loadSessionData() {
    if (isset($_SESSION['wa_session_data'])) {
      $this->data = $_SESSION['wa_session_data'];  
    }
    else {
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
      $this->writeSessionData();
    }
    if (isset($_SESSION['wa_return_url'])) {
      $this->returnUrl = $_SESSION['wa_return_url']['path'] . '?' . $_SESSION['wa_return_url']['query'];
    }
    else {
      $this->returnUrl = variable_get('webauth_destination', 'user');   
    }
  }
  
  public function isValidSession() {
    global $user;
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
    return $this->loggedIn;
  }
  
  public function getLdapGroups() {
    return $this->data['ldap_groups'];
  }
  
  public function getAtCookie() {
    if ($_COOKIE['webauth_at']) {
      $this->atCookie = $_COOKIE['webauth_at'];
  	} 
  }
  
  public function getWeblogin() {
    if (!$this->isLoggedIn) {
      header("Location: " . $this->authUrl);
    }
  }
  
  public function makeAuthUrl() {
  	// Figure out our return destination and save to a cookie for later consumption
  	$returnDest = '';
  	$wa_dest = trim(variable_get('webauth_destination',''));
  	if (isset($_REQUEST['destination']) && strcmp($_REQUEST['destination'], 'admin') !== FALSE) {
  		$returnDest = $_REQUEST['destination'];
  	} 
  	elseif ($forceNode != NULL) {
  		$returnDest = $forceNode;
  	} 
  	elseif (strlen($wa_dest) > 0) {
  		$returnDest = $wa_dest;
  	} 
  	elseif (isset($_REQUEST['q']) && strcmp($_REQUEST['q'], 'user/login') != 0) {
  		$returnDest = $_GET['q'];
  	}
  	
  	// Save query for later use.
  	$query = '';
  	foreach ($_GET as $key => $value) {
  		if (strlen($newquery) > 0) {
        $query .= '&'; 
  		}
  		$query .= $key . '=' . drupal_urlencode($value);
  	}
  	
  	// Save the return url
  	$_SESSION['wa_return_url'] = array(
  	  'path' => $returnDest,
  	  'query' => $query,
  	);
  	
  	// Create auth URL.
    $this->authUrl = url(variable_get('webauth_path', conf_path() . '/webauth') . '/login', 
                         array('absolute' => TRUE, 
                               'query' => array('destination' => $returnDest)));
  }
  
  public function getHeaderData() {
    $url = parse_url(url(variable_get('webauth_path', conf_path() . '/webauth') . '/check.php', array('absolute' => TRUE)));
    $sock = fsockopen('ssl://' . $url['host'] , 443, $errno, $errstr, 10);
  	if (!$sock) {
  		drupal_set_message('Unable to authenticate because of socket error: '.$errstr,'error');
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
  	
  	list($this->returnData['headers'], 
  	     $this->returnData['body']) = explode("\r\n\r\n", $return);

  	$headers = explode("\r\n", $this->returnData['headers']);
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
