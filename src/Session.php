<?php
namespace Vespula\Auth;

class Session {
    
    protected $key;
    
    public function __construct($key = null)
    {
        if (! $key) {
            $key = __CLASS__;
        }
        
        $this->key = $key;
        
        if (! isset($_SESSION[$key]) || ! isset($_SESSION[$key]['status'])) {
            $this->init();
        }
    }
    public function init($status = Auth::ANON)
    {
        $this->setStatus($status);
        $this->setUserName();
        $this->setUserData();
        $this->setActiveTime();
    }

    public function setStatus($status)
    {
        $_SESSION[$this->key]['status'] = $status;
    }
    
    public function getStatus()
    {
        return $_SESSION[$this->key]['status'];
    }
    
    public function getUserData()
    {
        return isset($_SESSION[$this->key]['userdata']) ? $_SESSION[$this->key]['userdata'] : [];
    }
    public function getUserName()
    {
        return isset($_SESSION[$this->key]['username']) ? $_SESSION[$this->key]['username'] : null;
    }
    
    public function setUserName($username = null)
    {
        $_SESSION[$this->key]['username'] = $username;
    }
    public function setUserData($userdata = [])
    {
        $_SESSION[$this->key]['userdata'] = $userdata;
    }
    
    public function setActiveTime($time = 0)
    {
        $_SESSION[$this->key]['activetime'] = $time;
    }
    
    public function getActiveTime()
    {
        return $_SESSION[$this->key]['activetime'];
    }
    
    
    
}