<?php
namespace Vespula\Auth;
use Vespula\Auth\Adapter\AdapterInterface;

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
     * @var \Vespula\Auth\Adapter
     */
    protected $adapter;
    protected $session;
    
    
    public function __construct(AdapterInterface $adapter, Session $session)
    {
        $this->adapter = $adapter;
        $this->session = $session;
    }

    
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
    
    public function logout()
    {
        $this->session->setStatus(Auth::ANON);
        $this->session->reset();
    }
    
    public function isValid()
    {
    	return $this->session->getStatus() == Auth::VALID;
    }
    
    public function isAnon()
    {
    	return $this->session->getStatus() == Auth::ANON;
    }
    
    public function isIdle()
    {
    	return $this->session->getStatus() == Auth::IDLE;
    }
    
    public function isExpired()
    {
    	return $this->session->getStatus() == Auth::EXPIRED;
    }

}