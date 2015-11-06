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
                'connect',
                'bind',
                'bindQuietly',
                'unbind',
                'search',
                'getValues',
                'firstEntry',
                'getUserDn',
                'explodeDn',
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
                ->method('connect')
                ->with('ldap.mycompany.org', '389')
                ->will($this->returnValue(true));
        
        $adapter->expects($this->once())
                ->method('bindQuietly')
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
                ->method('connect')
                ->with('ldap.mycompany.org', '389')
                ->will($this->returnValue(true));
    
        
        $adapter->expects($this->once())
                ->method('bind')
                ->with(true, 'cn=special,OU=MyCompany,OU=City,OU=Province', 'bindpass')
                ->will($this->returnValue(true));
        
        $adapter->expects($this->once())
                ->method('bindQuietly')
                ->with(true, 'cn=juser,OU=MyCompany,OU=City,OU=Province', 'password')
                ->will($this->returnValue(true));
                
        $adapter->expects($this->any())
                ->method('setLdapOptions')
                ->will($this->returnValue(true));
        

        $adapter->expects($this->once())
                ->method('search')
                ->with(true, 'OU=MyCompany,OU=City,OU=Province', 'samaccountname=juser')
                ->willReturn(true);
                
        $adapter->expects($this->once())
                ->method('firstEntry')
                ->with(true, true)
                ->willReturn(true);
        
        $adapter->expects($this->once())
                ->method('getUserDn')
                ->with(true, true)
                ->willReturn('cn=juser,OU=MyCompany,OU=City,OU=Province');
        
        $this->assertTrue($adapter->authenticate($credentials));
    }
}