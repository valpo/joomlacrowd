<?php
/**
 * @version    crowd.php 1
 * @package    Crowd
 * @subpackage Plugins
 * @license    GNU/GPL
 */
 
// Check to ensure this file is included in Joomla!
defined('_JEXEC') or die();
 
jimport('joomla.log.log');
jimport('joomla.plugin.plugin');
jimport('joomla.event.plugin');
jimport('joomla.error.log');
jimport('joomla.client.http');

 
class plgAuthenticationCrowd extends JPlugin
{
    /**
     * Constructor
     *
     * For php4 compatability we must not use the __constructor as a constructor for plugins
     * because func_get_args ( void ) returns a copy of all passed arguments NOT references.
     * This causes problems with cross-referencing necessary for the observer design pattern.
     *
     * @param object $subject The object to observe
     * @since 1.5
     */
    function plgAuthenticationCrowd(& $subject, $config) {
        parent::__construct($subject, $config);
        JLog::addLogger(array('text_file' => 'debug.crowd.log'));
        JLog::add('crowd 0.01 Start logging');
        //JLog::add('crowd config params: ' . $this->params);
    }
    
  // see rules.php
  protected function getUserGroups()
  {
    // Initialise variables.
    $db = JFactory::getDBO();
    $query = $db->getQuery(true);
    $query->select('a.id AS value, a.title AS text')
            ->from('#__usergroups AS a');
    $db->setQuery($query);
    $options = $db->loadObjectList();

    return $options;
  }
  
  /** after a failed login check if this user does not exists on crowd and delete it in this case */
  protected function checkDeleteUser($credentials) 
  {
  	JLog::add('check if we have to delete user ' . $credentials['username']);
  	$id = intval(JUserHelper::getUserId($credentials['username']));
  	if ($id < 1) {
  		JLog::add('user not known to joomla, do nothing');
  		return; // no such user in joomla, nothing to do for us
  	}
  	
  	// check whether this user exists in crowd
    $server = $this->params->get('crowd_url');
    $appname = $this->params->get('crowd_app_name');
    $apppass = $this->params->get('crowd_password');
    JLog::add('onUserAuthenticate: connecting to url ' . $server);
    $authcode = base64_encode($appname . ":" . $apppass);
    // JLog::add('auth code [' . $authcode . ']');

    // request cookie config from crowd
    $request_url = $server . '/rest/usermanagement/1/user?username=' . $credentials['username'];
    $request_header =  array('Accept' => 'application/json', 'Content-type' => 'application/xml',
                             'Authorization' => 'Basic ' . $authcode);
    $http = new JHttp;
    JLog::add('request url ' . $request_url);
    JLog::add('with headers ' . var_export($request_header, true));
    $result = $http->get($request_url, $request_header);
  	JLog::add('response: ' . var_export($result, true));
  	$obj = json_decode($result->body);
    JLog::add('msg: ' . $obj->reason);
    if ($obj->reason != 'USER_NOT_FOUND') {
    	JLog::add('crowd seems to know about this user, do not delete from joomla!');
    	return;
    }
  	
  	// delete this user
    $user = JUser::getInstance();
    $user->load($id);
    $user->delete();
    JLog::add('user deleted from joomla.');
  }
  
  /** creates a new joomla group, returns the resulting group id */
  protected function createGroup($gname)
  {
  	//$db = JFactory::getDbo();
    JLog::add('createGroup not yet implemented!');
  }

    
    /** Trust the sso flag, login without password */
    function doSSOLogin( $credentials, $options, &$response )
    {
	    JLog::add('crowd::onUserAuthenticate immediate login: ' . var_export($credentials, true));
	    $response->status = JAuthentication::STATUS_SUCCESS;
	    $response->email = $credentials['email'];
	    $response->fullname = $credentials['fullname'];
	    $response->username = $credentials['username'];
	    $response->error_message = '';
	    JLog::add('crowd: returning response: ' . var_export($response, true));
	    return true;
    }
 
 		/** checks username/password against crowd */
    function doCrowdLogin( $credentials, $options, &$response )
    {
      JLog::add('doing regular login');

      $server = $this->params->get('crowd_url');
      $appname = $this->params->get('crowd_app_name');
      $apppass = $this->params->get('crowd_password');
      JLog::add('onUserAuthenticate: connecting to url ' . $server);
      $authcode = base64_encode($appname . ":" . $apppass);
      // JLog::add('auth code [' . $authcode . ']');

      // request cookie config from crowd
      $request_url = $server . '/rest/usermanagement/1/config/cookie';
      $request_header =  array('Accept' => 'application/json', 'Content-type' => 'application/xml',
                               'Authorization' => 'Basic ' . $authcode);
      $http = new JHttp;
      JLog::add('request url ' . $request_url);
      JLog::add('with headers ' . var_export($request_header, true));
      $result = $http->get($request_url, $request_header);
      JLog::add('cookie config: ' . var_export($result, true));
      if (!$result or $result->code != 200) {
        $response->status = JAUTHENTICATE_STATUS_FAILURE;
        $response->error_message = 'Cannot fetch cookie config from crowd';
        return false;
      }
      $obj = json_decode($result->body);
      $cookieName = $obj->name;
      $cookieDomain = $obj->domain;
      JLog::add('cookie name: ' . $cookieName . ', domain: ' . $cookieDomain);

      // now trying to login
      $request_url = $server . '/rest/usermanagement/1/session?validate-password=true';
      JLog::add('request url ' . $request_url);
      $request_data = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' .
                      '<authentication-context>' .
                      '    <username>' . $credentials['username'] . '</username>' .
                      '    <password>' . $credentials['password'] . '</password>' .
                      '    <validation-factors>' .
                      '        <validation-factor>' .
                      '            <name>remote_address</name>' .
                      '            <value>' . $_SERVER['REMOTE_ADDR'] . '</value>' .
                      '        </validation-factor>' .
                      '    </validation-factors>' .
                      '</authentication-context>';
      #JLog::add('request data: ' . $request_data);
      $request_header =  array('Accept' => 'application/xml', 'Content-type' => 'application/xml',
                               'Authorization' => 'Basic ' . $authcode);
      JLog::add('with headers ' . var_export($request_header, true));
      $result = $http->post($request_url, $request_data, $request_header);
      JLog::add('response: ' . var_export($result, true));
      if (!$result or $result->code != 201) {
        JLog::add('have not got expected code 201, login failed');
        $response->status = JAUTHENTICATE_STATUS_FAILURE;
        $response->error_message = 'Login to crowd failed';
        return false;
      }
      JLog::add('fetching info from new location: ' . $result->headers['Location']);
      $result = $http->get($result->headers['Location'], $request_header);
      JLog::add('response: ' . var_export($result, true));
      if (!$result or $result->code != 200) {
        JLog::add('have not got expected code 200, login failed');
        $response->status = JAUTHENTICATE_STATUS_FAILURE;
        $response->error_message = 'Login to crowd failed';
        return false;
      }
      $xml = new SimpleXMLElement($result->body);
      $token = (string) $xml->token;
      JLog::add('token: ' . $token);

      // set response values for joomla auth
      $response->email = (string) $xml->user->email;
      $response->fullname = (string) $xml->user->{'display-name'};
      $response->username = (string) $xml->user['name'];
      $response->status = JAUTHENTICATE_STATUS_SUCCESS;
      $response->error_message = '';
      JLog::add('login successfull, returning: ' . var_export($response, true));

      // finally export our token as cookie
      JLog::add('set cookie ' . $cookieName . ' = ' . $token);
      setcookie($cookieName,$token, 0, "/", $cookieDomain,false,true);

      return true;
    }
    
    function handleGroups( $user, $credentials, $options, &$response ) 
    {
    	JLog::add('login succeeded, obtaining groups');
      $server = $this->params->get('crowd_url');
      $appname = $this->params->get('crowd_app_name');
      $apppass = $this->params->get('crowd_password');
      JLog::add('handleGroups: connecting to url ' . $server);
      $authcode = base64_encode($appname . ":" . $apppass);
      // JLog::add('auth code [' . $authcode . ']');

      // request groups from crowd
      $request_url = $server . '/rest/usermanagement/1/user/group/direct?username=' . $credentials['username'];
      $request_header =  array('Accept' => 'application/json', 'Content-type' => 'application/xml',
                               'Authorization' => 'Basic ' . $authcode);
      $http = new JHttp;
      JLog::add('request url ' . $request_url);
      JLog::add('with headers ' . var_export($request_header, true));
      $result = $http->get($request_url, $request_header);
      JLog::add('group config: ' . var_export($result, true));
      if (!$result or $result->code != 200) {
        $response->status = JAUTHENTICATE_STATUS_FAILURE;
        $response->error_message = 'Cannot fetch groups from crowd';
        return false;
      }
      $obj = json_decode($result->body);
      $groups = $obj->groups; // array containing all crowd groups of this user as objects with attr 'name'
      JLog::add('crowd groups: ' . var_export($groups, true));
      $response->groups = array();
      $allgroups = $this->getUserGroups(); // array of objects containing group name and joomla id as 'text' and 'value'
      JLog::add('joomla groups: ' . var_export($allgroups, true));
      $allgroupnames = array(); // array of joomla group names

      $groupmapping = explode(";",$this->params->get('crowd_group_map'));
      $groupmap = array();
      foreach ($groupmapping as $gm) {
      	$ml = explode(":",$gm);
      	if (count($ml) != 2 || intval($ml[1]) < 1) {
      		JLog::add('ignored mapping entry [' . $gm . ']');
      	}
      	else {
      		$groupmap[trim($ml[0])] = intval($ml[1]);
      	}
      }  
      JLog::add('groupmap: ' . var_export($groupmap,true));    
      
      foreach ($allgroups as $jgroup) {
      	array_push($allgroupnames, $jgroup->text);
      }
      
      // first remove user from all groups 
      foreach ($allgroups as $group) {
      	$res = JUserHelper::removeUserFromGroup($user->id, $group->value);
      	JLog::add('removed user from group ' . $group->text . ' with result ' . $res);
      }
      
      // now re-add all groups we have got from crowd            
      foreach ($groups as $group) {
      	JLog::add('got group: ' . $group->name);
      	array_push($response->groups, $group->name);
      	//array_push($user->groups, $group->name);
      	
        // check mapping
        if (array_key_exists($group->name, $groupmap)) {
        	$res = JUserHelper::addUserToGroup($user->id, $groupmap[$group->name]);
        	JLog::add('added user to mapped group ' . $group->name . ' result: ' . $res);
        	continue;
        }      	
      	
	      // create new groups if needed 
	      if (!in_array($group->name, $allgroupnames)) {
	      	JLog::add('create new group ' . $group->name);
	      	$gid = $this->createGroup($group->name);
	      }
	      else { // group already exists in joomla
	      	foreach ($allgroups as $g) {
	      		if ($g->text == $group->name) {
              try {
			      	  JUserHelper::addUserToGroup($user->id, $g->value);
			      	  JLog::add("added user " . $user->id . ' to group ' . $g->name . ' id: ' . $g->value);
              } catch (Exception $e) {
                JLog::add('adding user ' . $user->id . ' to group ' . $g->name . ' caused exception: ' . $e->getMessage());
              }
	      	  }
	      	}
	      }
      }
      try {
        $user->save();
      } catch (Exception $e) {
        JLog::add('saving user ' . $user->id . ' caused exception: ' . $e->getMessage());
      }

    }
    
    /**
     * This method should handle any authentication and report back to the subject
     *
     * @access    public
     * @param     array     $credentials    Array holding the user credentials ('username' and 'password')
     * @param     array     $options        Array of extra options
     * @param     object    $response       Authentication response object
     * @return    boolean
     * @since 1.5
     */
    function onUserAuthenticate( $credentials, $options, &$response )
    {
      JLog::add('onUserAuthenticate: auth started');
      $response->type = 'Crowd';
      $response->password_clear = "";
      $login_succeeded = false;
      if (array_key_exists('immediate', $options) and $options['immediate']) {
      	$login_succeeded = $this->doSSOLogin($credentials, $options, $response);
      }
      else {
      	$login_succeeded = $this->doCrowdLogin($credentials, $options, $response);
      }
	    if ($credentials['username'] == "admin") {
        JLog::add('admin login, neither check user nor groups');
        return login_succeeded; // do not more for admin user
      }
      if (! $login_succeeded) {
      	$this->checkDeleteUser($credentials);
      	return false;
      }
      $user = JUser::getInstance();
      if ($id = intval(JUserHelper::getUserId($response->username))) {
      }
      else {
      	JLog::add('creating new user ' . $response->username);
      	$user->set('id', 0);
				$user->set('name', $response->fullname);
				$user->set('username', $response->username);
				$user->set('email', $response->email);
	      $user->save();
	      $id = intval(JUserHelper::getUserId($response->username));
      }
      $user->id = $id;
      $response->id = $user->id;

      $this->handleGroups($user, $credentials, $options, $response);
      return true;
    }
}
?>

