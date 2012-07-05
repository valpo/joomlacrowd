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
        JLog::add('crowd Start logging');
        JLog::add('crowd config params: ' . $this->params);
        #JLog::add('config: ' . var_export($config, true));
        #$this->params = $config['params'];
        #JLog::add('config params: ' . $this->params);
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
        if (array_key_exists('immediate', $options) and $options['immediate']) {
          JLog::add('crowd::onUserAuthenticate immediate login: ' . var_export($credentials, true));
          $response->status = JAuthentication::STATUS_SUCCESS;
          $response->email = $credentials['email'];
          $response->fullname = $credentials['fullname'];
          $response->username = $credentials['username'];
          $response->error_message = '';
          JLog::add('crowd: returning response: ' . var_export($response, true));
          return true;
        }
        JLog::add('doing regular login');


        $server = $this->params->get('crowd_url');
        $appname = $this->params->get('crowd_app_name');
        $apppass = $this->params->get('crowd_password');
        JLog::add('onUserAuthenticate: connecting to url ' . $server);
        $authcode = base64_encode($appname . ":" . $apppass);
        JLog::add('auth code [' . $authcode . ']');

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
        $result = $http->post($request_url, $request_data, $request_header);
        JLog::add('response: ' . var_export($result, true));
        if (!$result or $result->code != 201) {
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

      $request_url = $server . '/rest/usermanagement/latest/authentication?username=' . $credentials['username'];
      $request_header =  array('Accept' => 'application/json', 'Content-type' => 'application/xml', 
                               'Authorization' => 'Basic ' . $authcode); 
      $request_method = 'POST';
      $request_data = '<?xml version="1.0" encoding="UTF-8"?><password><value>' 
                      . $credentials["password"] 
                      . '</value></password>';
      $options = array('headers' => $request_header,
                       'method' => $request_method,
                       'data'   => $request_data,
                       'max_redirects' => 3,
                       'timeout' => 102.0,
                       );
      $http = new JHttp;
      JLog::add('requesting url: ' . $request_url);
      JLog::add('with data: ' . $request_data);
      $result = $http->post($request_url, $request_data, $request_header);
      JLog::add("crowd response code " . $result->code . ", body: " . $result->body);
      JLog::add('result: ' . var_export($result, true));
      $obj = json_decode($result->body);
      JLog::add('json: ' . var_export($obj, true));

        if (!$result or $result->code != 200) {
            $response->status = JAUTHENTICATE_STATUS_FAILURE;
            $response->error_message = 'User does not exist or password is wrong';
            return false;
        }
        else {
          $response->email = $obj->email;
          $response->fullname = $obj->{'display-name'};
          $response->username = $obj->name;
          $response->status = JAUTHENTICATE_STATUS_SUCCESS;
          $response->error_message = '';
          JLog::add('authorized user name: ' . $response->username 
                    . ", fullname: " . $response->fullname 
                    . ", email: " . $response->email);

          # regular login, so now creating the sso token
          $http = new JHttp;
          $token = 'crowd.token_key'; #$this->params->get('cookieName');
          $request_url = $server . '/rest/usermanagement/latest/session';
          $request_data = '<?xml version="1.0" encoding="UTF-8"?>
                          <authentication-context>
                            <username>' . $credentials['username'] . '</username>
                            <password>' . $credentials['password'] . '</password>
                          </authentication-context>';

          #JLog::add('req: ' . $request_data);
          #JLog::add('url: ' . $request_url);
          #JLog::add('head: ' . var_export($request_header, true));
          $result = $http->post($request_url, $request_data, $request_header);
          JLog::add('result: ' . var_export($result, true));
          $location = explode('/', $result->headers['Location']);
          $token = $location[count($location)-1];
          JLog::add('token: ' . $token);
          $tokenName = $this->params->get('cookieName');
          $tokenDomain = $this->params->get('cookieDomain');
          setcookie($tokenName,$token, 0, "/", $tokenDomain,false,true);

          JLog::add('crowd: returning response: ' . var_export($response, true));
          return true;
        }
    }
}
?>

