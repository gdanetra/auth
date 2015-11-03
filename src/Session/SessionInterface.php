<?php
namespace Vespula\Auth\Session;

interface SessionInterface {

    /**
     * Get the current session status
     * 
     * @return string
     */
	public function getStatus();
	
	/**
	 * Set the status for the session
	 * 
	 * @param string $status
	 */
    public function setStatus($status);
    
    /**
     * Set the username in session store
     * 
     * @param string $username
     */
    public function setUsername($username);
    
    /**
     * Get the username from session store
     * 
     * @return string
     */
    public function getUsername();
    
    /**
     * Get extra userdata from the session store 
     * 
     * @see \Vespula\Auth\Adapter\AdapterInterface::lookupUserData()
     * @return array
     */
    public function getUserdata();
    
    /**
     * Set the userdata in session store
     * 
     * @param array $userdata
     */
    public function setUserdata($userdata);
    
    /**
     * Check to see if the session has gone idle based on idle time
     * 
     * @return boolean
     */
    public function isIdled();
    
    /**
     * Check to see if the session has expired based on expire time
     *
     * @return boolean
     */
    public function isExpired();
    
    /**
     * Clear certain session data (userdata, username)
     *
     */
    public function reset();

    
}