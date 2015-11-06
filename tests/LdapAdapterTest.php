<?php

class LdapAdapterTest extends \PHPUnit_Framework_TestCase {
    
    protected $adapter;
    
    public function setUp()
    {
        $uri = 'ldap.mycompany.org';
        $dn = 'cn=%s,OU=MyCompany,OU=City,OU=Province';
        
        $methods = [
            'ldap_connect',
            'ldap_bind',
            
        ];
        
        $constructor_params = [
            $uri,
            $dn
        ];
        
        $this->adapter = $this->getMock(
            '\Vespula\Auth\Adapter\Ldap', 
            $methods,
            $constructor_params
        );
        
        
    }
    
    public function testAuthenticate()
    {
        $credentials = [
            'username'=>'juser',
            'password'=>'password'
        ];
                
        $this->adapter->expects($this->once())
                      ->method('ldap_connect')
                      ->with('ldap.mycompany.org', '389')
                      ->will($this->returnValue(true));
        
        $this->adapter->expects($this->once())
                      ->method('ldap_bind')
                      ->with(true, 'cn=juser,OU=MyCompany,OU=City,OU=Province', 'password')
                      ->will($this->returnValue(true));
        
        $this->assertTrue($this->adapter->authenticate($credentials));
    }
}