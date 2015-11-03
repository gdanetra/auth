<?php
namespace Vespula\Auth\Adapter;

class Text implements AdapterInterface {
    
    protected $passwords = [];
    
    protected $userdata = [];

    public function setPassword($username, $password, $hash = PASSWORD_DEFAULT)
    {
        $this->passwords[$username] = password_hash($password, $hash);
    }
    public function authenticate($username, $password)
    {
        if (! isset($this->passwords[$username])) {
            return false;
        }
        return password_verify($password, $this->passwords[$username]);
    }
    
    public function setUserData($username, $data)
    {
    	$this->userdata[$username] = (array) $data;
    }
    
    
    public function lookupUserData($username)
    {
        return array_key_exists($username, $this->userdata) ? $this->userdata[$username] : [];
    }
    
    
}