<?php
/**
 * Class_oAuth
 *
 * @version  1.0
 * @package Stilero
 * @subpackage Class_oAuth
 * @author Daniel Eliasson (joomla@stilero.com)
 * @copyright  (C) 2013-jan-06 Stilero Webdesign (www.stilero.com)
 * @license	GNU General Public License version 2 or later.
 * @link http://www.stilero.com
 */

// no direct access
defined('_JEXEC') or die('Restricted access'); 

class OauthServer extends OauthCommunicator{
    
    private $OauthClient;
    private $OauthUser;
    private $nonce;
    private $timestamp;
    private $baseString;
    private $signature;
    private $signingKey;
    private $signingParams;
    private $authParams;
    private $requestMethod;
    private $headers;
    private $authHeader;
    private $url;
    private $data;
    
    const OAUTH_VERSION  = '1.0';
    const SIGN_METHOD = 'HMAC-SHA1';
    const REQ_METHOD_POST = 'POST';
    const REG_METHOD_GET = 'GET';
    
    
    public function __construct($url = "", $postVars = "", $config = "") {
        parent::__construct($url, $postVars, $config);
        $this->OauthClient = $OauthClient;
        $this->OauthUser = $OauthUser;
    }
    
    protected function createNonce($length=12){
        $characters = array_merge(range(0,9), range('A','Z'), range('a','z'));
        $length = $length > count($characters) ? count($characters) : $length;
        shuffle($characters);
        $prefix = microtime();
        $this->nonce = md5(substr($prefix . implode('', $characters), 0, $length));
    }
    
    protected function createTimestamp(){
        $this->timestamp = time();
    }
    
    private function getDefaults() {
        $defaults = array(
            'oauth_consumer_key' => $this->OauthClient->key,
            'oauth_nonce' => $this->nonce,
            'oauth_signature_method' => self::SIGN_METHOD,
            'oauth_version' => self::OAUTH_VERSION,
            'oauth_timestamp' => $this->timestamp,
        );
        if ( $this->OauthUser->$accessToken ){
            $defaults['oauth_token'] = $this->OauthUser->$accessToken;
        }
        foreach ($defaults as $key => $value) {
            $_defaults[$this->safeEncode($key)] = $this->safeEncode($value);
        }
        return $_defaults;
    }
    
    private function safeEncode($data) {
        if (is_array($data)) {
            return array_map(array($this, 'safe_encode'), $data);
        } else if (is_scalar($data)) {
            return str_ireplace( array('+', '%7E'), array(' ', '~'), rawurlencode($data) );
        } else {
            return '';
        }
    }
    
    private function safeDecode($data) {
        if (is_array($data)) {
            return array_map(array($this, 'safe_decode'), $data);
        } else if (is_scalar($data)) {
            return rawurldecode($data);
        } else {
            return '';
        }
    }
    
    private function createSigningKey() {
        $this->signingKey = $this->safeEncode($this->OauthClient->secret) . '&' . $this->safe_encode($this->OauthUser->tokenSecret);
    }
    
    private function createBaseString(){
        $base = array(
            $this->requestMethod,
            $this->url,
            $this->data
        );
        $this->baseString = implode('&', $this->safe_encode($base));
    }
    
    private function createSigningParams($params) {
        $this->signingParams = array_merge($this->get_defaults(), (array)$params);
        uksort($this->signingParams, 'strcmp');
        foreach ($this->signingParams as $key => $value) {
            $key = $this->safeEncode($key);
            $value = $this->safeEncode($value);
            $signingParams[$key] = $value;
            $keyValue[] = "{$key}={$value}";
        }
        $this->authParams = array_intersect_key($this->get_defaults(), $signingParams);
        $this->signingParams = implode('&', $keyValue);
    }
    
    private function setURL($url) {
        $parts = parse_url($url);
        $port = isset($parts['port']) ? $parts['port'] : '';
        $scheme = $parts['scheme'];
        $host = $parts['host'];
        $path = isset($parts['path']) ? $parts['path'] : '';
        $port or $port = ($scheme == 'https') ? '443' : '80';
        if(($scheme == 'https' && $port != '443') || ($scheme == 'http' && $port != '80')) {
            $host = "$host:$port";
        }
        $this->url = strtolower("$scheme://$host");
        $this->url .= $path;
    }
    
    private function setParams($params) {
        $this->signingParams = array_merge($this->getDefaults(), (array)$params);
        if (isset($this->signingParams['oauth_signature'])) {
            unset($this->signingParams['oauth_signature']);
        }
        uksort($this->signingParams, 'strcmp');
        foreach ($this->signingParams as $key => $value) {
            $key = $this->safeEncode($key);
            $value = $this->safeEncode($value);
            $_signing_params[$key] = $value;
            $kv[] = "{$key}={$value}";
        }
        $this->authParams = array_intersect_key($this->getDefaults(), $_signing_params);
        if (isset($_signing_params['oauth_callback'])) {
            $this->authParams['oauth_callback'] = $_signing_params['oauth_callback'];
            unset($_signing_params['oauth_callback']);
        }
        if (isset($_signing_params['oauth_verifier'])) {
            $this->authParams['oauth_verifier'] = $_signing_params['oauth_verifier'];
            unset($_signing_params['oauth_verifier']);
        }
        $this->signingParams = implode('&', $kv);
    }
    
    private function setBaseString() {
        $base = array(
            $this->requestMethod,
            $this->url,
            $this->signingParams
        );
        $this->baseString = implode('&', $this->safeEncode($base));
    }
    
    private function setSigningKey() {
        $this->signingKey = $this->safeEncode($this->OauthClient->secret) 
                . '&' . $this->safeEncode($this->OauthUser->tokenSecret);
    }
    
    private function setAuthHeader() {
        $this->headers = array();
        uksort($this->authParams, 'strcmp');
        foreach ($this->authParams as $key => $value) {
          $keyvalue[] = "{$key}=\"{$value}\"";
        }
        $this->authHeader = 'OAuth ' . implode(', ', $keyvalue);
    }
    
    private function setHeader(){
        $this->headers['Authorization'] = $this->authHeader;
        foreach ($this->headers as $key => $value) {
            $headers[] = trim($key . ': ' . $value);
        }
        $this->header = $headers;
    }
    
    private function sign($method, $url, $params, $useauth) {
        $this->requestMethod = $method;
        $this->setURL($url);
        $this->setParams($params);
        if ($useauth) {
            $this->setBaseString();
            $this->setSigningKey();

            $this->authParams['oauth_signature'] = $this->safeEncode(
                base64_encode(
                    hash_hmac(
                        'sha1', $this->baseString, $this->signingKey, true
                    )
                )
            );
            $this->setAuthHeader();
            $this->setHeader();
        }
    }
    
    public function request($method, $url, $params=array(), $useauth=true, $headers=array()) {
        $this->createNonce();
        $this->createTimestamp();
        if (!empty($headers)){
            $this->headers = array_merge((array)$this->headers, (array)$headers);
        }
        $this->sign($method, $url, $params, $useauth);
        $this->postVars = $this->signingParams;
        return $this->curlit();
    }
}
