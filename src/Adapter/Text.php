<?php
namespace Vespula\Auth\Adapter;

/**
 * This class is for authenticating users by simple text data. This is 
 * for testing purposes only and should not be used in production.
 * 
 * @author Jon Elofson <jon.elofson@gmail.com>
 *
 */
class Text implements AdapterInterface {
    
    /**
     * Error when no user found in the passwords array
     * 
     * @var string
     */
    const ERROR_NO_USER = 'ERROR_NO_USER';
    
   /**
    * 
    * @see setPassword()
    * @var array Hashed passwords keyed on username
    */
    protected $passwords = [];
    
    /**
     * 
     * @see setUserData()
     * @var array of userdata
     */
    protected $userdata = [];
    
    /**
     * @var string Debugging info
     */
    protected $error;

    /**
     * Set a User password 
     * 
     * @param string $username
     * @param string $password
     * @param string $hash Any hashing algorithm used in password_hash()
     */
    public function setPassword($username, $password, $hash = PASSWORD_DEFAULT)
    {
        $this->passwords[$username] = password_hash($password, $hash);
    }
    
    /**
     * {@inheritDoc}
     * @see \Vespula\Auth\Adapter\AdapterInterface::authenticate()
     */
    public function authenticate(array $credentials)
    {
        // explicit vs `extract`
        $username = $credentials['username'];
        $password = $credentials['password'];
        
        if (! isset($this->passwords[$username])) {
            $this->error = Text::ERROR_NO_USER;
            return false;
        }
        return password_verify($password, $this->passwords[$username]);
    }
    
    /**
     * Set user-specific data
     * 
     * @param string $username
     * @param array $data
     */
    public function setUserData($username, array $data)
    {
        $this->userdata[$username] = $data;
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \Vespula\Auth\Adapter\AdapterInterface::lookupUserData()
     */
    public function lookupUserData($username)
    {
        return array_key_exists($username, $this->userdata) ? $this->userdata[$username] : [];
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
    
    
}