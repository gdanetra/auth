<?php

class LdapAdapterTest extends \PHPUnit_Framework_TestCase {
    
    protected $methods;
    protected $params_dn;
    protected $params_bind;
    
    
    public function setUp()
    {
        $uri = 'ldap.mycompany.org';
        $dn = 'cn=%s,OU=MyCompany,OU=City,OU=Province';
        
        $ldap_options = [
            'LDAP_OPTION_A'=>3,
        ];
        $bind_options = [
                'basedn'=>'OU=MyCompany,OU=City,OU=Province',
                'binddn'=>'cn=special,OU=MyCompany,OU=City,OU=Province',
                'bindpw'=>'bindpass',
                'filter'=>'samaccountname=%s'
        ];
        
        $attributes = [
                'givenname',
                'mail'
        ];
        
        $this->methods = [
                'ldap_connect',
                'ldap_bind',
                'ldap_unbind',
                'ldap_search',
                'ldap_get_values',
                'ldap_first_entry',
                'ldap_get_dn',
                'ldap_explode_dn',
                'setLdapOptions',
        ];
        
        $this->params_dn = [
                $uri,
                $dn,
                null, 
                $ldap_options,
                $attributes
        ];
        $this->params_bind = [
                $uri,
                null,
                $bind_options,
                $ldap_options,
                $attributes
        ];
    }
    
    public function testAuthenticateDn()
    {
        $credentials = [
            'username'=>'juser',
            'password'=>'password'
        ];
        
        $adapter = $this->getMock('\Vespula\Auth\Adapter\Ldap', $this->methods, $this->params_dn);
                
        $adapter->expects($this->once())
                ->method('ldap_connect')
                ->with('ldap.mycompany.org', '389')
                ->will($this->returnValue(true));
        
        $adapter->expects($this->once())
                ->method('ldap_bind')
                ->with(true, 'cn=juser,OU=MyCompany,OU=City,OU=Province', 'password')
                ->will($this->returnValue(true));        
        
        $adapter->expects($this->any())
                ->method('setLdapOptions')
                ->will($this->returnValue(true));
        
        
        
        $this->assertTrue($adapter->authenticate($credentials));
    }
    
    public function testAuthenticateBind()
    {
        $credentials = [
                'username'=>'juser',
                'password'=>'password'
        ];
    
        $adapter = $this->getMock('\Vespula\Auth\Adapter\Ldap', $this->methods, $this->params_bind);
    
        $adapter->expects($this->once())
                ->method('ldap_connect')
                ->with('ldap.mycompany.org', '389')
                ->will($this->returnValue(true));
    
        
        $adapter->expects($this->at(2))
                ->method('ldap_bind')
                ->with(true, 'cn=special,OU=MyCompany,OU=City,OU=Province', 'bindpass')
                ->will($this->returnValue(true));
        
        $adapter->expects($this->at(6))
                ->method('ldap_bind')
                ->with(true, 'cn=juser,OU=MyCompany,OU=City,OU=Province', 'password')
                ->will($this->returnValue(true));
                
        $adapter->expects($this->any())
                ->method('setLdapOptions')
                ->will($this->returnValue(true));
        

        $adapter->expects($this->once())
                ->method('ldap_search')
                ->with(true, 'OU=MyCompany,OU=City,OU=Province', 'samaccountname=juser')
                ->willReturn(true);
                
        $adapter->expects($this->once())
                ->method('ldap_first_entry')
                ->with(true, true)
                ->willReturn(true);
        
        $adapter->expects($this->once())
                ->method('ldap_get_dn')
                ->with(true, true)
                ->willReturn('cn=juser,OU=MyCompany,OU=City,OU=Province');
        
        $this->assertTrue($adapter->authenticate($credentials));
    }
}