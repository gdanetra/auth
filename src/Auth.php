<?php
namespace Vespula\Auth;
use Vespula\Auth\Adapter\AdapterInterface;

class Auth {
    /**
     * User is valid
     */
    const VALID = 'valid';
    /**
     * User is not valid
     */
    const INVALID = 'invalid';
    
    /**
     * User is not logged in
     */
    const ANON = 'anonymous';
    
    /**
     * User is not logged in
     */
    const IDLE = 'idle';
    
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
            $this->session->setStatus(Auth::VALID);
            $userdata = $this->adapter->lookupUserData($username);
            $this->session->setUserData($userdata);
            $this->session->setUserName($username);
        } else {
            $this->session->setStatus(Auth::INVALID);
        }
    }
    
    public function logout()
    {
        $this->session->init();
    }
    
    public function update()
    {
        // used to update idle time etc
        // need to get cookie lifetime etc.
    }
    
    public function getUserData()
    {
        return $this->session->getUserData();
    }
    public function getUserName()
    {
        return $this->session->getUserName();
    }
    
    public function isValid()
    {
        return $this->session->getStatus() == Auth::VALID;
    }
    
    
}