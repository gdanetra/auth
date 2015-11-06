<?php
namespace Vespula\Auth\Adapter;
use PDO;

class SqlTest extends \PHPUnit_Framework_TestCase {
    
    protected $pdo;
    protected $adapter;
    protected $cols;
    
    public function setUp()
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->createDatabase();
        $this->cols = [
            'username',
            'bcryptpass'=>'password',
            'fullname'=>'full_name',
            'email'
        ];
        $where = 'active=1';
        $this->adapter = new \Vespula\Auth\Adapter\Sql($this->pdo, 'user', $this->cols, $where);
    }
    
    public function createDatabase()
    {
        $sql = "CREATE TABLE user (
            username VARCHAR(12) PRIMARY KEY, 
            fullname VARCHAR(50), 
            email VARCHAR(150), 
            bcryptpass VARCHAR(200),
            active INT
        )";
        
        $this->pdo->query($sql);
        
        $rows = [
            [
                'username'=>'juser',
                'fullname'=>'Joe User',
                'email'=>'juser@awesome.com',
                'bcryptpass'=>password_hash('password', PASSWORD_DEFAULT),
                'active'=>1
            ],
            [
                'username'=>'mclovin',
                'fullname'=>'McLovin',
                'email'=>'mclovin@awesome.com',
                'bcryptpass'=>password_hash('secret', PASSWORD_DEFAULT),
                'active'=>0
            ]
        ];

        
        $insert = "INSERT INTO user (username, fullname, email, bcryptpass, active) "
                . "VALUES (:username, :fullname, :email, :bcryptpass, :active)";
        
        $statement = $this->pdo->prepare($insert);
        
        foreach ($rows as $row) {
            $statement->execute($row);
        }
    }
    
    public function testAuthenticate()
    {
        $credentials = [
            'username'=>'juser',
            'password'=>'password'
        ];
        
        $valid = $this->adapter->authenticate($credentials);
        
        $this->assertTrue($valid);
    }
    
    public function testAuthenticateFailedNoRow()
    {
        $credentials = [
            'username'=>'mclovin',
            'password'=>'secret'
        ];
        
        $this->adapter->authenticate($credentials);
        
        $this->assertEquals(Sql::ERROR_NO_ROWS, $this->adapter->getError());
    }
    
    public function testAuthenticateFailedBadCreds()
    {
        $credentials = [
            'username'=>'juser',
            'password'=>'bladfads'
        ];
        
        $valid = $this->adapter->authenticate($credentials);
        
        $this->assertFalse($valid);
    }
    
    
    public function testAuthenticateBadWhere()
    {
        $this->setExpectedException('PDOException');
        
        $where = "blah=1";
        $adapter = new \Vespula\Auth\Adapter\Sql($this->pdo, 'user', $this->cols, $where);
        
        $credentials = [
            'username'=>'mclovin',
            'password'=>'secret'
        ];
        
        $adapter->authenticate($credentials);
    }
    
    public function testLookupUserdata()
    {
        
        $credentials = [
            'username'=>'juser',
            'password'=>'password'
        ];
        
        $this->adapter->authenticate($credentials);
        $info = $this->adapter->lookupUserData('juser');
        $expected = [
            'full_name'=>'Joe User',
            'email'=>'juser@awesome.com'
        ];
        $this->assertEquals($expected, $info);
    }
    
    public function testFixColsNoUsername()
    {
        $this->setExpectedException('Exception', Sql::ERROR_USERNAME_COL);
        
        $credentials = [
            'username'=>'juser',
            'password'=>'password'
        ];
        $cols = [
            'asdfasd',
            'password'
        ];
        $adapter = new \Vespula\Auth\Adapter\Sql($this->pdo, 'user', $cols);
        $adapter->authenticate($credentials);
    }
    
    public function testFixColsNoPassword()
    {
        $this->setExpectedException('Exception', Sql::ERROR_PASSWORD_COL);
        
        $credentials = [
            'username'=>'juser',
            'password'=>'password'
        ];
        $cols = [
            'username',
            'xqsd'
        ];
        $adapter = new \Vespula\Auth\Adapter\Sql($this->pdo, 'user', $cols);
        $adapter->authenticate($credentials); 
    }
}