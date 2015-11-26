<?php
namespace Vespula\Auth;
use Vespula\Auth\Adapter\AdapterInterface;
use Vespula\Auth\Session\SessionInterface;

/**
 * Simple authentication package with session management and adapter interfaces
 * 
 * <code>
 * $adapter = new \Vespula\Auth\Adapter\Sql(...);
 * $session = new \Vespula\Auth\Session\Session();
 * $auth = new \Vespula\Auth\Auth($adapter, $session)
 * 
 * if ($something...) {
 *     // filter these first
 *     $credentials = [
 *         'username'=>$_POST['username'],
 *         'password'=>$_POST['password']
 *     ];
 *     $auth->login($credentials);
 *     if ($auth->isValid()) {
 *         // Yay....
 *     } else {
 *         // Nay....
 *         // Wonder why? Any errors?
 *         $error = $adapter->getError(); // may be no errors. Just bad creds
 *     }
 * }
 * 
 * if ($something...) {
 *     $auth->logout();
 * }
 * 
 * if ($auth->isValid()) {
 *     // Access some part of site
 * }
 * 
 * if ($auth->isIdle()) {
 *     // Sitting around for too long
 * }
 * 
 * if ($auth->isExpired()) {
 *     // Sitting around way too long!
 * }
 * 
 * @author Jon Elofson <jon.elofson@gmail.com>
 *
 */
class Auth {
    
    /**
     * User is valid
     */
    const VALID = 'VALID';
    
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
     * 
     * @return AdapterInterface
     */
    public function getAdapter()
    {
        return $this->adapter;
    }
    
    /**
     * 
     * @return SessionInterface
     */
    public function getSession()
    {
        return $this->session;
    }
    
    /**
     * Login using the adapter's authenticate method
     * 
     * @param array $credentials Array with keys `username` and `password`.
     * @param string $password
     */
    public function login($credentials)
    {
        if (! array_key_exists('username', $credentials) || ! array_key_exists('password', $credentials)) {
            throw new Exception('Invalid credentials array. Must have keys `username` and `password`.');
        }
        
        $valid = $this->adapter->authenticate($credentials);
        
        if ($valid) {
            // Set status
            $this->session->setStatus(Auth::VALID);
            
            // Set username
            $this->session->setUsername($credentials['username']);
            
            // Set userdata
            $this->session->setUserdata($this->adapter->lookupUserData($credentials['username']));    
        } else {
            // Make sure the user is not valid if they tried to login and creds were wrong.
            $this->logout();
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
     * Get the person's username
     * 
     * @return string
     */
    public function getUsername()
    {
        return $this->session->getUsername();
    }
    
    /**
     * Get the user's userdata
     * 
     * @return array
     */
    public function getUserdata($key = null)
    {
        $userdata = $this->session->getUserdata();
        if ($key) {
            if (array_key_exists($key, $userdata)) {
                return $userdata[$key];
            }
            return null;
        }
        return $this->session->getUserdata();
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
     * Note, this will automatically log the person out if true and set the status to ANON
     * 
     * @return boolean
     */
    public function isIdle()
    {
        $idle = $this->session->getStatus() == Auth::IDLE;
        if ($idle) {
            $this->logout();
            return true;
        }
        return false;
    }
    
    /**
     * Did the user's session expire?
     * 
     * Note, this will automatically log the person out if true and set the status to ANON
     * 
     * @return boolean
     */
    public function isExpired()
    {
        $expired = $this->session->getStatus() == Auth::EXPIRED;
        if ($expired) {
            $this->logout();
            return true;
        }
        return false;
    }
    
    /**
     * Check the session's data and see if the user has been idle too long or expired
     * 
     * Set the appropriate status in the session.
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