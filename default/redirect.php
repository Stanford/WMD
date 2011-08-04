<?php
setcookie('WA_HEADERS', serialize($_SERVER), 0, '/', '.stanford.edu', TRUE, TRUE);
header('Location: /group/wmddev/cgi-bin/drupal2/sites/all/modules/webauth/auth/login');