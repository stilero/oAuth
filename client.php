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

class Client{
    
    public $key;
    public $secret;
    
    public function __construct($key, $secret) {
        $this->key = $key;
        $this->secret = $secret;
    }
}
