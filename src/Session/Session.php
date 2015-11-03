<?php
namespace Vespula\Auth\Session;
use Vespula\Auth\Exception;

class Session implements SessionInterface {
    
    /**
     * The session segment (array key) used to segregate this session data
     * 
     * @var string
     */
	protected $key;
	
	/**
	 * The max idle time allowed. 0 for no check. Default is session.gc_maxlifetime
	 * 
	 * @var integer
	 */
    protected $idle;
    
    /**
     * The time allowed before the session expires. Default is session.cookie_lifetime.
     * 0 means no check
     * 
     * @var array
     */
    protected $expire;
    
    /**
     * The friendly reference to the session data
     * 
     * @var array
     */
    protected $store = [];
    
    /**
     * Constructor
     * 
     * @param integer $idle Set an idle max time allowed. 0 for no max.
     * @param integer $expire Set the time when session expires. 0 for no expire.
     */
    public function __construct($idle = null, $expire = null)
    {
        $this->key = __CLASS__;
        
        if (! isset($_SESSION[$this->key])) {
            $_SESSION[$this->key] = [
                    'status'=>null,
                    'timestamp'=>time(),
                    'username'=>null,
                    'userdata'=>null,
            		'interval'=>0
            ];
        }
        $this->store =& $_SESSION[$this->key];

        $this->setIdle($idle);
        $this->setExpire($expire);
        $this->updateInterval();
  
    }

    /**
     * Update the time since last request. Used to determine idle/expired
     * 
     */
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
    
    /**
     * Set the idle time. Check that it is not greater than session.gc_maxlifetime.
     * 
     * @param integer $idle
     * @throws \Exception
     */
    public function setIdle($idle)
    {
        $this->idle = ini_get('session.gc_maxlifetime');
        if ($idle !== null) {
            $idle = (int) $idle;
            if ($idle > ini_get('session.gc_maxlifetime')) {
                throw new Exception('Idle time greater than gc_maxlifetime');
            }
            $this->idle = $idle;
        }
    }
    
    /**
     * Set the max time before expiry. Must not be greater than session.cookie_lifetime
     * 
     * @param integer $expire
     * @throws \Exception
     */
    public function setExpire($expire)
    {
        $this->expire  = ini_get('session.cookie_lifetime');
        if ($expire !== null) {
            $expire = (int) $expire;
            $cookie_lifetime = ini_get('session.cookie_lifetime');
            if ($cookie_lifetime > 0 && $expire > $cookie_lifetime) {
                throw new Exception('Expire time greater than cookie_lifetime');
            }
            $this->expire = $expire;
        }
    }
    
    /**
     * {@inheritDoc}
     * 
     * @see \Vespula\Auth\Session\SessionInterface::isIdled()
     */
    public function isIdled()
    {
        return $this->idle > 0 && $this->store['interval'] >= $this->idle;
    }
    
    /**
     * {@inheritDoc}
     * 
     * @see \Vespula\Auth\Session\SessionInterface::isExpired()
     */
    public function isExpired()
    {
        return $this->expire > 0 && $this->store['interval'] >= $this->expire;
    }
    
    /**
     * {@inheritDoc}
     * 
     * @see \Vespula\Auth\Session\SessionInterface::reset()
     */
    public function reset()
    {
        $this->store['username'] = null;
        $this->store['userdata'] = null;
    }
    
    /**
     * Get the current timestamp (time of current request)
     * 
     * @return integer
     */
    public function getTimestamp()
    {
        return $this->store['timestamp'];
    }
    
    /**
     * Get the time since last request
     * 
     * @return integer
     */
    public function getInterval()
    {
        return $this->store['interval'];
    }
    
    /**
     * {@inheritDoc}
     * 
     * @see \Vespula\Auth\Session\SessionInterface::setStatus()
     */
    public function setStatus($status)
    {
        $this->store['status'] = $status;
    }
    
    /**
     * {@inheritDoc}
     *
     * @see \Vespula\Auth\Session\SessionInterface::getStatus()
     */
    public function getStatus()
    {
        return $this->store['status'];
    }
    
    /**
     * {@inheritDoc}
     *
     * @see \Vespula\Auth\Session\SessionInterface::setUsername()
     */
    public function setUsername($username)
    {
        $this->store['username'] = $username;
    }
    
    /**
     * {@inheritDoc}
     *
     * @see \Vespula\Auth\Session\SessionInterface::getUsername()
     */
    public function getUsername()
    {
        return $this->store['username'];
    }
    
    /**
     * {@inheritDoc}
     *
     * @see \Vespula\Auth\Session\SessionInterface::setUserdata()
     */
    public function setUserdata($userdata)
    {
        $this->store['userdata'] = $userdata;
        
    }
    
    /**
     * {@inheritDoc}
     *
     * @see \Vespula\Auth\Session\SessionInterface::getUserdata()
     */
    public function getUserdata()
    {
        return $this->store['userdata'];
    }
    
}