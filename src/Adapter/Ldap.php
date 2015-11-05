<?php
namespace Vespula\Auth\Adapter;
use Vespula\Auth\Exception;

/**
 * This class is for authenticating users against Active Directory using LDAP.
 * 
 * Please note the suppressed warning on the ultimate ldap_bind in authenticate()
 *
 * @author Jon Elofson <jon.elofson@gmail.com>
 *
 */
class Ldap implements AdapterInterface {
    
    /**
     * Debugging info
     * 
     * @var string
     */
    const ERROR_NO_DN = 'ERROR_NO_DN';
    
    /**
     * An LDAP connection
     * 
     * @var resource
     */
    protected $conn;
    
    /**
     * The ldap server uri
     * 
     * @var string
     */
    protected $uri;
    
    /**
     * Port to connect to
     * 
     * @var integer
     */
    protected $port;
    
    /**
     * The dn format, if known, for authenticating. If null, $bind_options must be set
     * 
     * Format like this 'cn=%s, OU=City,OU=Country'
     * 
     * @var string
     */
    protected $dn;
    
    /**
     * An array of bind options for finding a user's DN
     * 
     * Keys are:
     * 
     * `basedn`: The base dn to search through
     * `binddn`: The dn used to bind to
     * `bindpw`: A password used to bind to the server using the binddn
     * `filter`: A filter used to search for the user. Eg. samaccountname=%s
     * 
     * @var array
     */
    protected $bind_options;
    
    /**
     * LDAP options you want set after connecting. As an array with $key and $value
     * 
     * <code>
     * $ldap_options = [
     *     LDAP_OPT_PROTOCOL_VERSION=>3
     * ];
     * </code>
     * 
     * @var unknown
     */
    protected $ldap_options;
    
    /**
     * Extra attributes from the LDAP entry you want placed in the userdata array
     * 
     * Note: this doesn't support aliases yet. You can't say ['internet_address'=>'email']
     * 
     * @var array
     */
    protected $attributes;
    
    /**
     * Debugging error
     * 
     * @var string
     */
    protected $error;
    
    /**
     * Constructor
     * 
     * @param string $uri ldap.mycompany.org
     * @param string $dn
     * @param array $bind_options Optional. Required if no $dn
     * @param array $ldap_options Optional LDAP options 
     * @param array $attributes Attributes to retrieve from AD and populate $userdata
     * @param integer $port The port number. Default 389
     * @throws Exception
     */
    public function __construct($uri, $dn = null, $bind_options = null, $ldap_options = null, $attributes= null, $port = 389)
    {
        if (! extension_loaded('ldap')) {
            throw new Exception('LDAP extension not loaded');
        }

        $this->uri = $uri;
        $this->port = (int) $port;
        $this->dn = $dn;
        $this->bind_options = (array) $bind_options;
        $this->ldap_options = (array) $ldap_options;
        $this->attributes = (array) $attributes;
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \Vespula\Auth\Adapter\AdapterInterface::authenticate()
     */
    public function authenticate(array $credentials) 
    {
        extract($credentials);
        
        if (empty($username)) {
            return false;
        }
        if (empty($password)) {
            return false;
        }

        $this->conn = ldap_connect($this->uri, $this->port);
        
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
        // If a DN was not found, that means they did not supply one, or it was not found in Active Directory
        // Don't continue without a DN, but let's capture an error for debugging.
        
        if (! $this->dn) {
            $this->error = Ldap::ERROR_NO_DN;
            return false;
        }
        // Suppress the warning here so that even in dev environments, we don't see it.
        // I don't want a warning if they type their password in wrong.
        // All other ldap functions should output appropriate warnings if enabled.
        $bind = @ldap_bind($this->conn, $this->dn, $password);
        return $bind;
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \Vespula\Auth\Adapter\AdapterInterface::lookupUserData()
     */
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
    
    /**
     * 
     * {@inheritDoc}
     * @see \Vespula\Auth\Adapter\AdapterInterface::getError()
     */
    public function getError()
    {
        return $this->error;
    }
    
    
    /**
     * Parse returned entry and make the userdata more friendly
     * 
     * @param resource $conn LDAP connection
     * @param resource $entry Entry identifier
     * @param array $attribs Attribs to collect
     * @return array 
     */
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
    
    /**
     * Ensure bind options are set properly
     * 
     * @param array $bind_options
     * @throws Exception
     */
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
    
    /**
     * Find a user's dn using $bind_options. This is common in organizations 
     * that have multiple DNs for groups of individuals. Search a base DN for the userid, 
     * then return that user's fully-qualified DN that can be used to authenticate against.
     * 
     * Returns false if no dn is found
     * 
     * @param resource $conn LDAP connection
     * @param string $username
     * @param array $bind_options
     * @throws Exception
     * @return boolean|string
     */
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
    
    /**
     * Set ldap options after connecting.
     * 
     * @param resource $conn LDAP connection
     * @param array $options Options
     */
    protected function setLdapOptions($conn, $options)
    {
        foreach ($options as $option=>$value) {
            ldap_set_option($conn, $option, $value);
        }
    }
}