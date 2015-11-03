<?php
namespace Vespula\Auth;
use Vespula\Auth\Adapter\AdapterInterface;
use Vespula\Auth\Session\SessionInterface;

class Auth {
    
    /**
     * User is valid
     */
    const VALID = 'VALID';
    
    /**
     * User is not valid
     */
    const INVALID = 'INVALID';
    
    /**
     * User is not logged in
     */
    const ANON = 'ANON';
    
    /**
     * User is idle
     */
    const IDLE = 'IDLE';
    
    /**
     * User is expired
     */
    const EXPIRED = 'EXPIRED';
    
    /**
     * The adapter used to authenticate 
     * 
     * @var \Vespula\Auth\Adapter\AdapterInterface
     */
    protected $adapter;
    
    /**
     * The session used to save state
     * 
     * @var \Vespula\Auth\Session\SessionInterface
     */
    protected $session;
    
    /**
     * 
     * @param AdapterInterface $adapter
     * @param SessionInterface $session
     */
    public function __construct(AdapterInterface $adapter, SessionInterface $session)
    {
        $this->adapter = $adapter;
        $this->session = $session;
        if ($this->session->getStatus() == null) {
        	$this->session->setStatus(Auth::ANON);
        }
        
        if ($this->session->getStatus() == Auth::VALID) {
            $this->checkIdleExpire();
        }
    }
	
    /**
     * Login using the adapter's authenticate method
     * 
     * @param string $username
     * @param string $password
     */
    public function login($username, $password)
    {
        $valid = $this->adapter->authenticate($username, $password);
        
        if ($valid) {
            // Set status
            $this->session->setStatus(Auth::VALID);
            
            // Set username
            $this->session->setUsername($username);
            
            // Set userdata
            $this->session->setUserdata($this->adapter->lookupUserData($username));    
        }
        
    }
    
    /**
     * Logout. Sets the status to ANON and clears session data
     */
    public function logout()
    {
        $this->session->setStatus(Auth::ANON);
        $this->session->reset();
    }
    
    /**
     * Is the user valid (logged in)
     * 
     * @return boolean
     */
    public function isValid()
    {
        return $this->session->getStatus() == Auth::VALID;
    }
    
    /**
     * Is the user anonymous (logged out)
     * 
     * @return boolean
     */
    public function isAnon()
    {
        return $this->session->getStatus() == Auth::ANON;
    }
    
    /**
     * Is the user idle?
     * 
     * @return boolean
     */
    public function isIdle()
    {
        return $this->session->getStatus() == Auth::IDLE;
    }
    
    /**
     * Did the user's session expire?
     * 
     * @return boolean
     */
    public function isExpired()
    {
        return $this->session->getStatus() == Auth::EXPIRED;
    }
    
    /**
     * Check the session's data and see if the user has been idle too long or expired
     */
    protected function checkIdleExpire()
    {
        if ($this->session->isIdled()) {
            $this->session->setStatus(Auth::IDLE);
        }
         
        if ($this->session->isExpired()) {
            $this->session->setStatus(Auth::EXPIRED);
        }
    }

}