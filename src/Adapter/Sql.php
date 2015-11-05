<?php
namespace Vespula\Auth\Adapter;
use Vespula\Auth\Exception;

class Sql implements AdapterInterface {
    
    const ERROR_NO_ROWS = 'ERROR_NO_ROWS';
    
    protected $pdo;
    protected $cols = [];
    protected $from;
    protected $where;
    protected $userdata = [];
    protected $error;
    
    public function __construct(\Pdo $pdo, $from, $cols, $where = null)
    {
        $this->pdo = $pdo;
        $this->from = $from;
        $this->cols = $cols;
        $this->where = $where;
    }
    
    
    public function authenticate($credentials)
    {
        extract($credentials);
        
        $cols = $this->fixCols();

        $where = "username = :username";
        if ($this->where) {
            $where .= " AND $this->where";
        }
        $query = "SELECT $cols FROM {$this->from} WHERE $where LIMIT 1";
        $statement = $this->pdo->prepare($query);
        if (! $statement->execute([':username'=>$username])) {
            $error = $this->buildStatementError($statement->errorInfo());
            throw new Exception($error);
        }

        $row = $statement->fetch(\PDO::FETCH_ASSOC);
        
        if (! $row) {
            $this->error = Sql::ERROR_NO_ROWS;
            return false;
        }
        $this->userdata = $row;
        return password_verify($password, $row['password']);
  
    }
    
    public function getError()
    {
        return $this->error;
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
        foreach ($this->userdata as $key=>$val) {
            if (! in_array($key, $ignore)) {
                $info[$key] = $val;
            }
        }
        return $info;
    }

}