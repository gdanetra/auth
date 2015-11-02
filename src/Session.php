<?php
namespace Vespula\Auth;

class Session {
    
    protected $key;
    protected $idle;
    protected $expire;
    protected $store = [];
    
    public function __construct($idle = null, $expire = null)
    {

        $this->key = __CLASS__;
        
        $this->initialize();
        $this->setIdle($idle);
        $this->setExpire($expire);
        $this->updateInterval();
        
        if ($this->getStatus() == Auth::VALID) {
        	$this->checkIdleExpire();
        }
        
    }
    
    protected function initialize()
    {
    	if (! isset($_SESSION[$this->key])) {
    		$_SESSION[$this->key] = [
    			'status'=>Auth::ANON,
    			'timestamp'=>time(),
    			'username'=>null,
    			'userdata'=>null,
    		];
    	}
    	$this->store =& $_SESSION[$this->key];
    }
    
    protected function setIdle($idle)
    {
    	$this->idle = ini_get('session_gc_maxlifetime');
    	if ($idle !== null) {
    		$idle = (int) $idle;
    		if ($idle > ini_get('session.gc_maxlifetime')) {
    			throw new \Exception('Idle time greater than gc_maxlifetime');
    		}
    		$this->idle = $idle;
    	}
    }
    
    protected function setExpire($expire)
    {
    	$this->expire  = ini_get('session_gc_maxlifetime');
    	if ($expire !== null) {
    		$expire = (int) $expire;
    		$cookie_lifetime = ini_get('session.cookie_lifetime');
    		if ($cookie_lifetime > 0 && $expire > $cookie_lifetime) {
    			throw new \Exception('Expire time greater than cookie_lifetime');
    		}
    		$this->expire = $expire;
    	}
    }
    
    protected function updateInterval()
    {
    	$now = time();
    	if (! array_key_exists('timestamp', $this->store)) {
    		$this->store['timestamp'] = $now;
    	}
    	$prev = $this->store['timestamp'];
    	$this->store['interval'] = $now - $prev;
    	$this->store['timestamp'] = $now;
    }

    protected function checkIdleExpire()
    {
    	
    	if ($this->idle > 0 && $this->store['interval'] >= $this->idle) {
    		$this->setStatus(Auth::IDLE);
    	}
    	
    	if ($this->expire > 0 && $this->store['interval'] >= $expire) {
    		$this->setStatus(Auth::EXPIRED);
    	}
    }
    
    public function reset()
    {
    	$this->store['username'] = null;
    	$this->store['userdata'] = null;
    }
    
    public function getTimestamp()
    {
    	return $this->store['timestamp'];
    }
    
    public function setStatus($status = Auth::ANON)
    {
    	$this->store['status'] = $status;
    }
    
    public function getStatus()
    {
    	return $this->store['status'];
    }
    
    public function setUsername($username)
    {
    	$this->store['username'] = $username;
    }
    
    public function getUsername()
    {
    	return $this->store['username'];
    }
    
    public function setUserdata($userdata)
    {
    	$this->store['userdata'] = $userdata;
    	
    }
    
    public function getUserdata()
    {
    	return $this->store['userdata'];
    }
    
}