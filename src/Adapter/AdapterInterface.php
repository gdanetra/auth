<?php
namespace Vespula\Auth\Adapter;

interface AdapterInterface {
	

	public function authenticate($username, $password);
	public function lookupUserData($username);

	
}