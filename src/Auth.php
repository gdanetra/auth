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
     * User is idle
     */
    const IDLE = 'idle';
    
    /**
     * User is expired
     */
    const EXPIRE = 'expire';
    
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
            $this->session->setActiveTime(time());
        } else {
            $this->session->setStatus(Auth::INVALID);
        }
    }
    
    public function logout($status = Auth::ANON)
    {
        $this->session->init($status);
    }
    
    public function update()
    {
        if ($this->session->getStatus() == Auth::VALID) {
            $idle = ini_get('session.gc_maxlifetime');
            $expire = ini_get('session.cookie_lifetime');

            $now = time();
            if ( ($now - $this->session->getActiveTime()) >= $idle) {
                $this->logout(Auth::IDLE);
                return;
            }
            
            if (($now - $this->session->getActiveTime()) >= $expire && $expire != 0) {
                $this->logout(Auth::EXPIRE);
                return;
            }
            
            $this->session->setActiveTime($now);
        }
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
    public function isIdle()
    {
        return $this->session->getStatus() == Auth::IDLE;
    }
    public function isExpired()
    {
        return $this->session->getStatus() == Auth::EXPIRE;
    }
    
    
}