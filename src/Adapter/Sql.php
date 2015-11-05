<?php
namespace Vespula\Auth\Adapter;
use Vespula\Auth\Exception;

/**
 * This class is for authenticating users against a database table. 
 *
 * @author Jon Elofson <jon.elofson@gmail.com>
 *
 */
class Sql implements AdapterInterface {
    
    /**
     * Debuggind info
     * 
     * @var string
     */
    const ERROR_NO_ROWS = 'ERROR_NO_ROWS';
    
    /**
     * a \PDO object
     * 
     * @var \PDO
     */
    protected $pdo;
    
    /**
     * Array of columns that must have 'username' and 'password' in them 
     * 
     * You can supply them in the form of 'realcolumn'=>'alias'. For example:
     * 
     * <code>
     * // select `bcryptpass` AS `password`, `username`, `internet_address` AS `email`
     * $cols = [
     *     'bcryptpass'=>'password',
     *     'username',
     *     'internet_address'=>'email'
     * ];
     * // In this example, the password col and username col requirements are met via an alias
     * //  on the bcryptpass col.
     * </code>
     * 
     * 
     * @var array
     */
    protected $cols = [];
    
    /**
     * What table to use
     * 
     * @var string
     */
    protected $from;
    
    /**
     * Any additional where conditions.
     * 
     * @var string
     */
    protected $where;
    
    /**
     * Userdata to be collected and stored in session from the row. 
     * 
     * Note that username and password are NOT included here.
     * 
     * From the above example, 'email' would be the only key in this array
     * 
     * @var array
     */
    protected $userdata = [];
    
    /**
     * Debugging error info
     * 
     * @var string
     */
    protected $error;
    
    /**
     * Constructor 
     * 
     * @param \PDO $pdo
     * @param string $from
     * @param array $cols
     * @param string $where
     */
    public function __construct(\PDO $pdo, $from, array $cols, $where = null)
    {
        $this->pdo = $pdo;
        $this->from = $from;
        $this->cols = $cols;
        $this->where = $where;
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \Vespula\Auth\Adapter\AdapterInterface::authenticate()
     * @todo Use binding for the additional $where
     */
    public function authenticate(array $credentials)
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
        
        // Simple debugging info (could not find the user in the table based on the where clause)
        if (! $row) {
            $this->error = Sql::ERROR_NO_ROWS;
            return false;
        }
        $this->userdata = $row;
        return password_verify($password, $row['password']);
  
    }
    
    /**
     * 
     * {@inheritDoc}
     * @see \Vespula\Auth\Adapter\AdapterInterface::lookupUserData()
     */
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
    
    /**
     * 
     * {@inheritDoc}
     * @see \Vespula\Auth\Adapter\AdapterInterface::getError()
     */
    public function getError()
    {
        return $this->error;
    }
    
    /**
     * Ensure the cols array contains required keys and set up aliases
     * 
     * @throws Exception
     * @return string
     */
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
    
    /**
     * Generate a person-friendly PDO statement error
     * 
     * @param array $info
     * @return string
     */
    protected function buildStatementError($info)
    {
        if (isset($info[2])) {
            return $info[2];
        }
        return 'SQLSTATE error code: ' . $info[0];
    }
}