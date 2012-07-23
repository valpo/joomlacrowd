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

    /**
     * @param object $subject The object to observe
     * @param array $config  An array that holds the plugin configuration
     */
    public function plgSystemCrowdSSO(&$subject, $config) {
        parent::__construct($subject, $config);
        JLog::addLogger(array('text_file' => 'debug.crowd.log'));
        JLog::add('crowd sso created');
    }

    /**
     * Performs Single Sign-On or Single Sing-Out
     * when the cookie is set/unset.
     */
    public function onAfterInitialise() {
        JLog::add('crowd sso onAfterInitialise');
        if ((bool)$this->params->get(self::CONFIG_DISABLEADMIN) && JFactory::getApplication()->isAdmin()) {
            return; //No SSO for administrator seciton
        }
        $user = JFactory::getUser();
        JLog::add("current user is: ". $user->username .", guest: " . (int)$user->guest);
        $token = $this->_readToken();
        if ($user->guest and empty($token)) { # case 1
          JLog::add('case 1: user is guest and crowd token is empty - thats fine, do nothing');
          return;
        }
        else if ($user->guest and !empty($token)) { # case 2
          JLog::add('case 2: user is guest and we have a crowd token - try sso login');
          $this->_tryLogin($token);
        }
        else if (!$user->guest and empty($token)) { # case 3
          JLog::add('case 3: user is not guest, but crowd token is empty - thats bad, logout');
          $this->_tryLogout($user);
        }
        else if (!$user->guest) { # case 5 without case 4
          JLog::add('case 4 or 5: user is not guest, who cares..., we do nothing');
          return; # do nothing, we just keep her
        }
        else {
          JLog::add('crowdsso::onAfterInitialise: unknown case, strange things going on here...');
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
      $request_header = array('Accept' => 'application/json', 'Content-type' => 'application/xml', 
                              'Authorization' => 'Basic ' . $authcode);
      $http = new JHttp;
      $result = $http->get($request_url, $request_header);
      JLog::add('crowdsso response: ' . $result->code . ', data: ' . $result->body);
      if ($result->code != 200) {
        JLog::add('crowdsso login failed');
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

    function onUserLoginFailure($response) {
      JLog::add('crowdsso::onUserLoginFailure for ' . $response['username'] . ' . because: ' . $response['error_message']);
    }
}
