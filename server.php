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

class Server{
    
    private $nonce;
    private $timestamp;
    private $signature;
    static $version  = '1.0';
    static $signMethod = 'HMAC-SHA1';
    
    
    public function __construct($config="") {
        $defaultConfig = array(
            'configName' => 'configVal'
        );
        if(isset($config) && !empty($config)){
            $defaultConfig = array_merge($defaultConfig, $config);
        }
        $this->_config = $defaultConfig;
    }
    
    protected function createNonce($length=12, $include_time=true){
        $characters = array_merge(range(0,9), range('A','Z'), range('a','z'));
        $length = $length > count($characters) ? count($characters) : $length;
        shuffle($characters);
        $prefix = $include_time ? microtime() : '';
        $this->nonce = md5(substr($prefix . implode('', $characters), 0, $length));
    }
    
    protected function createTimestamp(){
        $this->timestamp = time();
    }
    
}
