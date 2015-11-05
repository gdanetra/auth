<?php
namespace Vespula\Auth\Adapter;

interface AdapterInterface {
    
	/**
	 * validate the username and password.
	 * 
	 * @param string $username
	 * @param string $password
	 * @return boolean
	 */
    public function authenticate($username, $password);
    
    /**
     * Find extra userdata. This will be stored in the session
     * 
     * @return array
     */
    public function lookupUserData($username);
    
    public function getError();

    
}