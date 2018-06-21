<?php
/**
 * @version	    1.0
 * @package		JPlugin
 * @subpackage	System
 * @copyright	(C) 2012 Open Source Matters. All rights reserved.
 * @license		GNU/GPL, see LICENSE.php
 *
 * Single Sign On with crowd
 */

// Check to ensure this file is included in Joomla!
defined('_JEXEC') or die('Restricted access');


jimport('joomla.plugin.plugin');
jimport('joomla.user.authentication');
jimport('joomla.error.log');

/**
 * Single Sign-On System Plugin
 *
 * 5 different cases depending on whether we have a valid Joomla user and a valid crowd token:
 * 
 * 1. no user, no token -> keep her as guest
 * 2. no user, valid token -> auto login
 * 3. valid user, no token -> logout
 * 4. valid user, wrong token -> logout, login (not checked to avoid crowd lookup -> speedup!)
 * 5. valid user, valid token -> ok.
 *
 *
 * @author     Mathias Waack
 * @package		 JPlugin
 * @subpackage System
 */
class plgSystemCrowdSSO extends JPlugin {

    const CONFIG_DISABLEADMIN = 'disable_admin';
    const CONFIG_COOKIENAME = 'cookieName';
	const LOGGER_CATEGORY = 'crowdsso';

    /**
     * @param object $subject The object to observe
     * @param array $config  An array that holds the plugin configuration
     */
    public function plgSystemCrowdSSO(&$subject, $config) {
        parent::__construct($subject, $config);
        JLog::addLogger(array('text_file' => 'debug.crowd.log'), JLog::DEBUG, array(self::LOGGER_CATEGORY));
        JLog::add('crowd sso 0.01 created', JLog::DEBUG, self::LOGGER_CATEGORY);
    }

    /**
     * Performs Single Sign-On or Single Sing-Out
     * when the cookie is set/unset.
     */
    public function onAfterInitialise() {
        JLog::add('crowd sso onAfterInitialise', JLog::DEBUG, self::LOGGER_CATEGORY);
        if ((bool)$this->params->get(self::CONFIG_DISABLEADMIN) && JFactory::getApplication()->isAdmin()) {
            return; //No SSO for administrator section
        }
        $user = JFactory::getUser();
        JLog::add("current user is: ". $user->username .", guest: " . (int)$user->guest . ", admin: " . JFactory::getApplication()->isAdmin(), JLog::DEBUG, self::LOGGER_CATEGORY);
        $token = $this->_readToken();
        if ($user->guest and empty($token)) { # case 1
          JLog::add('case 1: user is guest and crowd token is empty - thats fine, do nothing', JLog::DEBUG, self::LOGGER_CATEGORY);
          return;
        }
        else if ($user->guest and !empty($token)) { # case 2
          JLog::add('case 2: user is guest and we have a crowd token - try sso login', JLog::DEBUG, self::LOGGER_CATEGORY);
          $this->_tryLogin($token);
        }
        else if (!$user->guest and empty($token)) { # case 3
          JLog::add('case 3: user is not guest, but crowd token is empty - thats bad, logout', JLog::DEBUG, self::LOGGER_CATEGORY);
          $this->_tryLogout($user);
        }
        else if (!$user->guest) { # case 4
          JLog::add('case 4: user is not guest and we have a token - we do nothing', JLog::DEBUG, self::LOGGER_CATEGORY);
          return; # do nothing, we just keep her
        }
        else {
          JLog::add('crowdsso::onAfterInitialise: unknown case, strange things going on here...', JLog::DEBUG, self::LOGGER_CATEGORY);
        }
    }

    protected function _readToken() {
        $cookiename = $this->params->get(self::CONFIG_COOKIENAME);
        $cookiename = str_replace('.', '_', $cookiename); # joomla replaces this?
        if (!isset($_COOKIE[$cookiename])) return "";
        $token = $_COOKIE[$cookiename];
        return $token;
    }

    protected function _tryLogin($token) {
      JLog::add("_tryLogin");
      $server = $this->params->get('crowd_url');
      $appname = $this->params->get('crowd_app_name');
      $apppass = $this->params->get('crowd_password');
      $authcode = base64_encode($appname . ":" . $apppass);
      $request_url = $server . '/rest/usermanagement/latest/session/' . $token;
      $request_header = array('Accept' => 'application/json', 'Content-Type' => 'application/xml', 
                              'Authorization' => 'Basic ' . $authcode);
      $http = new JHttp;
      $result = $http->get($request_url, $request_header);
      JLog::add('crowdsso response: ' . $result->code . ', data: ' . $result->body, JLog::DEBUG, self::LOGGER_CATEGORY);
      if ($result->code != 200) {
        JLog::add('crowdsso login failed', JLog::DEBUG, self::LOGGER_CATEGORY);
        return -1;
      }
      $obj = json_decode($result->body);
      # JLog::add('json: ' . var_export($obj, true));

      # $dispatcher =& JDispatcher::getInstance();
      # $dispatcher->trigger('onUserAuthenticate', 
      $credentials = array('username' => $obj->user->name,
                           'email' => $obj->user->email,
                           'fullname' => $obj->user->{'display-name'},
                           'password' => 'x'); 
      $options = array('return' => JFactory::getURI()->toString(), 'immediate' => true);
      # JAuthentication::getInstance()->authenticate($credentials, $options);
      JApplication::getInstance('site')->login($credentials, $options);

    }

    protected function _tryLogout($user) {
      JLog::add("_tryLogout");
      JFactory::getApplication()->logout($user->id);
      JFactory::getApplication()->redirect('/');
    }

	function onUserLogout($user, $options = array()) {
	  $cookiename = $this->params->get(self::CONFIG_COOKIENAME);
      $cookiekey = str_replace('.', '_', $cookiename); # joomla replaces this?
	  if (isset($_COOKIE[$cookiekey])) {
	    unset($_COOKIE[$cookiekey]);
	    setcookie($cookiename, '', time() - 3600, '/');
        JLog::add('crowdsso::onUserLogout - deleted cookie ' . $cookiename, JLog::DEBUG, self::LOGGER_CATEGORY); 
	  }
	}

    function onUserLoginFailure($response) {
      JLog::add('crowdsso::onUserLoginFailure for ' . $response['username'] . ' . because: ' . $response['error_message'], JLog::DEBUG, self::LOGGER_CATEGORY);
    }
}
