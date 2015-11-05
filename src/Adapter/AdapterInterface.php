<?php
namespace Vespula\Auth\Adapter;

interface AdapterInterface {
    
    /**
     * validate the username and password.
     * 
     * @param array $credentials Array with keys 'username' and 'password'
     * @return boolean
     */
    public function authenticate($credentials);
    
    /**
     * Find extra userdata. This will be stored in the session
     * 
     * @return array
     */
    public function lookupUserData($username);
    
    public function getError();

    
}