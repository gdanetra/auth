<?php
namespace Vespula\Auth\Adapter;

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
        /*
        $username_col = array_shift($this->cols);
        $password_col = array_shift($this->cols);
        $cols = implode(', ', $this->cols);
        */
        $where = "username = :username";
        if ($this->where) {
            $where .= " AND $this->where";
        }
        $query = "SELECT $cols FROM {$this->from} WHERE $where LIMIT 1";
        $statement = $this->pdo->prepare($query);
        $statement->execute([':username'=>$username]);
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
            throw new \Exception('Missing username col');
        }
        if (! in_array('password', $this->cols)) {
            throw new \Exception('Missing password col');
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
    
    
}