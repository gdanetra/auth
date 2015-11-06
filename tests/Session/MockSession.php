<?php
namespace Vespula\Auth\Session;

use Vespula\Auth\Session\SessionInterface;
use Vespula\Auth\Auth;
class MockSession implements SessionInterface {
	
	protected $store = [
		'status'=>Auth::ANON
	];
	protected $idle;
	protected $expire;
	
	public function __construct($idle = null, $expire = null)
	{
		$this->idle = $idle;
		$this->expire = $expire;
	}
	
	public function getStatus()
	{
		return $this->store['status'];
	}
	public function setStatus($status)
	{
		$this->store['status'] = $status;
	}
	
	public function setUsername($username)
	{
		$this->store['username'] = $username;
	}
	public function getUsername()
	{
		return $this->store['username'];
	}
	public function getUserdata()
	{
		return $this->store['userdata'];
	}
	public function setUserdata($data)
	{
		$this->store['userdata'] = (array) $data;
	}
	
	public function isIdled()
	{
		return true;
	}
	
	public function isExpired()
	{
		return false;
	}
	
	public function reset()
	{
		$this->store['username'] = null;
		$this->store['userdata'] = null;
	}
}