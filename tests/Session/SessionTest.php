<?php
namespace Vespula\Auth\Session;

session_start();

use Vespula\Auth\Session\Session;
use Vespula\Auth\Auth;

class SessionTest extends \PHPUnit_Framework_TestCase {
    
    protected $session;
    protected $initial = 0;
    
    public function setUp()
    {
        unset($_SESSION['Vespula\\Auth\\Session\\Session']);
        $this->initial = time();
        $this->session = new Session();
        
        $_SESSION['Vespula\\Auth\\Session\\Session']['interval'] = 1200;
    }
    
    public function testInitial()
    {
        $this->assertNull($this->session->getStatus());
        $this->assertNull($this->session->getUsername());
        $this->assertEmpty($this->session->getUserdata());
    }
    
    public function testSetGetUsername()
    {
        $this->session->setUsername('juser');
        $this->assertEquals($this->session->getUsername(), 'juser');
    }
    
    public function testSetGetUserdata()
    {
        $userdata = [
            'fullname'=>'Joe User'
        ];
        $this->session->setUserdata($userdata);
        $this->assertEquals($this->session->getUserdata(), $userdata);
    }
    
    public function testReset()
    {
        $this->session->reset();
        $this->assertNull($this->session->getUsername());
        $this->assertNull($this->session->getUserdata());
    }
    
    public function testSetGetStatus()
    {
        $this->session->setStatus(Auth::ANON);
        $this->assertEquals(Auth::ANON, $this->session->getStatus());
    }
    
    public function testSetGetIdle()
    {
        $this->session->setIdle(1200);
        $this->assertEquals(1200, $this->session->getIdle());
    }
    
    public function testSetGetExpire()
    {
        $this->session->setExpire(3600);
        $this->assertEquals(3600, $this->session->getExpire());
    }
    
    /**
     * @expectedException \Vespula\Auth\Exception
     */
    public function testSetIdleException()
    {
        ini_set('session.gc_maxlifetime', 1200);
        $max = 1201;
        $this->session->setIdle($max);
        
    }
    
    /**
     * @expectedException \Vespula\Auth\Exception
     */
    public function testSetExpireException()
    {
        ini_set('session.cookie_lifetime', 1800);
        $max = 1801;
        $this->session->setExpire($max);
    
    }
    
    public function testIsIdled()
    {
        $this->session->setIdle(1100);
        $this->assertTrue($this->session->isIdled());
        
        $this->session->setIdle(0);
        $this->assertFalse($this->session->isIdled());
    }
    
    public function testIsExpired()
    {
        $this->session->setExpire(1100);
        $this->assertTrue($this->session->isExpired());
        
        $this->session->setExpire(0);
        $this->assertFalse($this->session->isExpired());
    }
    
}
