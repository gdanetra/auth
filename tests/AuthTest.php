<?php
namespace Vespula\Auth;

include 'Session/MockSession.php';

use \Vespula\Auth\Auth;
use \Vespula\Auth\Adapter\Text;



class AuthTest extends \PHPUnit_Framework_TestCase {
	
	protected $auth;
	protected $session;
	protected $adapter;
	protected $userdata = ['fullname'=>'Joe User'];
	
	public function setUp()
	{
		
		$this->session = new \Vespula\Auth\Session\MockSession();
		

		$this->adapter = new Text();
		$this->adapter->setPassword('juser', 'password');
		$this->adapter->setUserData('juser', $this->userdata);
		
		$this->auth = new Auth($this->adapter, $this->session);
		$this->auth->logout();
	}

	public function testLogin()
	{
		$credentials = [
		    'username'=>'juser',
		    'password'=>'password'
		];
	    $this->auth->login($credentials);
		$status = $this->session->getStatus();
		$this->assertEquals($status, Auth::VALID);
		
		$this->assertEquals($this->userdata, $this->session->getUserdata());
		$this->assertEquals('juser', $this->session->getUsername());
	}
	
	public function testLoginFailed()
	{
	    $credentials = [
            'username'=>'juser',
            'password'=>'------'
	    ];
	    
	    $this->session->setStatus(Auth::ANON);
		$this->session->reset();
		$this->auth->login($credentials);
		$status = $this->session->getStatus();
		$this->assertEquals($status, Auth::ANON);
	}
	
	public function testLogout()
	{
	    $credentials = [
            'username'=>'juser',
            'password'=>'password'
	    ];
	    
	    $this->auth->login($credentials);
		$this->auth->logout();
		
		$this->assertEquals(Auth::ANON, $this->session->getStatus());
		$this->assertNull($this->session->getUsername());
		$this->assertNull($this->session->getUserdata());
		
	}
	
	public function testIsValid()
	{
		$this->session->setStatus(Auth::VALID);
		$this->assertTrue($this->auth->isValid());
		
		$this->session->setStatus(Auth::ANON);
		$this->assertFalse($this->auth->isValid());
	}
	
	public function testIsAnon()
	{
		$this->session->setStatus(Auth::ANON);
		$this->assertTrue($this->auth->isAnon());
	
		$this->session->setStatus(Auth::VALID);
		$this->assertFalse($this->auth->isAnon());
	}
	
	public function testIsIdle()
	{
		$this->session->setStatus(Auth::IDLE);
		$this->assertTrue($this->auth->isIdle());
	
		$this->session->setStatus(Auth::VALID);
		$this->assertFalse($this->auth->isIdle());
	}
	
	public function testIsExpired()
	{
		$this->session->setStatus(Auth::EXPIRED);
		$this->assertTrue($this->auth->isExpired());
	
		$this->session->setStatus(Auth::VALID);
		$this->assertFalse($this->auth->isExpired());
	}
}