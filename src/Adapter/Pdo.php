<?php
namespace Vespula\Auth\Adapter;
use Vespula\Auth\Exception;

class Pdo implements AdapterInterface {
    
    protected $pdo;
    protected $cols = [
        'username',
        'bcryptpass'=>'password'
    ];
    protected $from;
    protected $where;
    protected $row = [];
    
    public function __construct(\Pdo $pdo, $from, $where = null)
    {
        $this->pdo = $pdo;
        $this->from = $from;
        $this->where = $where;
    }
    
    public function setCols($cols = [])
    {
        $this->cols = $cols;
    }
    public function authenticate($username, $password)
    {
        $cols = $this->fixCols();

        $where = "username = :username";
        if ($this->where) {
            $where .= " AND $this->where";
        }
        $query = "SELECT $cols FROM {$this->from} WHERE $where LIMIT 1";
        $statement = $this->pdo->prepare($query);
        if (! $statement->execute([':username'=>$username])) {
        	$error = $this->buildStatementError($statement->errorInfo());
        	trigger_error($error, E_USER_WARNING);
        	return false;
        }

        $row = $statement->fetch(\PDO::FETCH_ASSOC);
        
        if (! $row) {
        	return false;
        }
        $this->row = $row;
        return password_verify($password, $row['password']);
  
    }
    
    protected function fixCols()
    {
        $cols = [];

        if (! in_array('username', $this->cols)) {
            throw new Exception('Missing username col');
        }
        if (! in_array('password', $this->cols)) {
            throw new Exception('Missing password col');
        }

        foreach ($this->cols as $key=>$col) {
            if (is_string($key)) {
                $cols[] = "`$key` AS `$col`"; 
            } else {
                $cols[] = "`$col`";
            }
        }
        return implode(", ", $cols);
        
    }
    
    protected function buildStatementError($info)
    {
    	if (isset($info[2])) {
    		return $info[2];
    	}
    	return 'SQLSTATE error code: ' . $info[0];
    }
    
    public function lookupUserData($username)
    {
        $info = [];
        $ignore = ['username', 'password'];
        foreach ($this->row as $key=>$val) {
            if (! in_array($key, $ignore)) {
                $info[$key] = $val;
            }
        }
        return $info;
    }
    
    public function getStatementError()
    {
    	return $this->statement_error;
    }
    
    
}