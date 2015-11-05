<?php
namespace Vespula\Auth\Adapter;

class Text implements AdapterInterface {
    
    const ERROR_NO_USER = 'ERROR_NO_USER';
    
    protected $passwords = [];
    protected $userdata = [];
    protected $error;

    public function setPassword($username, $password, $hash = PASSWORD_DEFAULT)
    {
        $this->passwords[$username] = password_hash($password, $hash);
    }
    public function authenticate($credentials)
    {
        extract($credentials);
        
        if (! isset($this->passwords[$username])) {
            $this->error = Text::ERROR_NO_USER;
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
    
    public function getError()
    {
        return $this->error;
    }
    
    
}