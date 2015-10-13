<?php
namespace Vespula\Auth\Adapter;

class Text extends AbstractAdapter implements AdapterInterface {
    
    protected $passwords = [];

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
    
    
    public function lookupUserData($username)
    {
        $userdata = [
            'fullname' => 'Jon Elofson'
        ];
        return $userdata;
    }
    
    
}