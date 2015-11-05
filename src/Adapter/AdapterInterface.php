<?php
namespace Vespula\Auth\Adapter;

interface AdapterInterface {
    
    /**
     * validate the username and password.
     * 
     * @param array $credentials Array with keys 'username' and 'password'
     * @return boolean
     */
    public function authenticate(array $credentials);
    
    /**
     * Find extra userdata. This will be stored in the session
     * 
     * @return array Userdata specific to the adapter
     */
    public function lookupUserData($username);
    
    /**
     * Get the most recent error for debugging purposes
     * 
     * @return string Error (should be a constant)
     */
    public function getError();

    
}