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
     * Find extra userdata by username. This will be stored in the session
     * 
     * @param string $username
     * @return array
     */
    public function lookupUserData($username);

    
}