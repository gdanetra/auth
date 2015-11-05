<?php
namespace Vespula\Auth\Adapter;
use Vespula\Auth\Exception;

class Ldap implements AdapterInterface {
    
    const ERROR_NO_DN = 'ERROR_NO_DN';
    
    protected $conn;
    protected $uri;
    protected $dn;
    protected $bind_options;
    protected $ldap_options;
    protected $attributes;
    protected $error;
    
    public function __construct($uri, $dn, $bind_options = null, $ldap_options = null, $attributes= null)
    {
        if (! extension_loaded('ldap')) {
            throw new Exception('LDAP extension not loaded');
        }

        $this->uri = $uri;
        $this->dn = $dn;
        $this->bind_options = (array) $bind_options;
        $this->ldap_options = (array) $ldap_options;
        $this->attributes = (array) $attributes;
        
        // Need to catch the warning when a bind fails.
        set_error_handler([$this, 'handleError'], E_WARNING);
    }
    
    public function authenticate($credentials) 
    {
        extract($credentials);
        
        if (empty($username)) {
            return false;
        }
        if (empty($password)) {
            return false;
        }

        $this->conn = ldap_connect($this->uri);
        
        if (! $this->conn) {
            throw new Exception('Could not bind to ldap server');
        }
       
        $this->setLdapOptions($this->conn, $this->ldap_options);
        
        $username = addcslashes($username, '\\&!|=<>,+-"\';*');
        
        if ($this->dn) {
            $this->dn = sprintf($this->dn, $username);
            
        } else {
            $this->checkBindOptions($this->bind_options);
            $this->dn = $this->findDn($this->conn, $username, $this->bind_options);
        }
        
        // No exception here, but set an error for debugging.
        if (! $this->dn) {
            $this->error = Ldap::ERROR_NO_DN;
            return false;
        }
        
        $bind = ldap_bind($this->conn, $this->dn, $password);
        return $bind;
    }
    
    public function lookupUserData($username)
    {
        $userdata = [];
        $dn_parts = ldap_explode_dn($this->dn, 0);
        $resource = ldap_search($this->conn, $this->dn, $dn_parts[0], $this->attributes);
        if ($resource) {
            $entry = ldap_first_entry($this->conn, $resource);
            if ($entry !== false) {
                $userdata = $this->parseUserAttribs($this->conn, $entry, $this->attributes);
            }
        }
        ldap_unbind($this->conn);
        return $userdata;
    }
    
    public function getError()
    {
        return $this->error;
    }

    protected function parseUserAttribs($conn, $entry, $attribs)
    {
        $userdata = [];
        foreach ($attribs as $attrib) {
            $vals = ldap_get_values($conn, $entry, $attrib);
            $count = array_pop($vals);
            if ($count == 1) {
                $userdata[$attrib] = $vals[0];
            } else {
                $userdata[$attrib] = $vals;
            }
        }
        
        return $userdata;
    }
    
    protected function checkBindOptions($bind_options)
    {
        if (! array_key_exists('basedn', $bind_options)) {
            throw new Exception('Missing basedn in bind options');
        }
        if (! array_key_exists('binddn', $bind_options)) {
            throw new Exception('Missing binddn in bind options');
        }
        if (! array_key_exists('bindpw', $bind_options)) {
            throw new Exception('Missing bindpw in bind options');
        }
        if (! array_key_exists('filter', $bind_options)) {
            throw new Exception('Missing filter in bind options');
        }
    }
    
    protected function findDn($conn, $username, $bind_options)
    {

        $dn = false;
        extract($bind_options);

        $bind = ldap_bind($conn, $binddn, $bindpw);
        if (! $bind) {
            throw new Exception('Could not bind to basedn');
        }
    
        $searchfilter = sprintf($filter, $username);

        $resource = ldap_search($conn, $basedn, $searchfilter);
    
        if ($resource === false) {
            throw new Exception('The LDAP DN search failed');
        }
        
        $first = ldap_first_entry($conn, $resource);
        if ($first !== false) {
            $dn = ldap_get_dn($conn, $first);
        }
        return $dn;
    }
    
    
    protected function setLdapOptions($conn, $options)
    {
        foreach ($options as $option=>$value) {
            ldap_set_option($conn, $option, $value);
        }
    }
    
    protected function handleError($errno, $errstr)
    {
        $this->error = $errstr;
    }
}