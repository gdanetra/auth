# README #

A simple, flexible authentication class that is easy to set up and understand.

Exceptions may be thrown so you will likely want to catch them using a `try catch` block.

Exceptions should only be thrown due to incorrect configuration or server issues, etc. Exceptions are not thrown when the authentication fails due to bad username and password.

## Table of Contents ##

* [Installation](#markdown-header-installation)
* [Usage](#markdown-header-usage)
* [Adapters](#markdown-header-adapters)
    * [Text Adapter](#markdown-header-text-adapter)
    * [Sql Adapter](#markdown-header-sql-adapter)
    * [LDAP Adapter](#markdown-header-ldap-adapter) (with and without a known user DN)


## Installation ##

Clone or download and make available as you see fit. It's PSR-4 compliant so you can reference the source folder in a composer.json folder, for example. 

```
// example composer.json
{
    "autoload": {
        "psr-4": {
        "Vespula\\Auth\\": "your/path"
        }
    }
}
```

Or via composer via `composer require vespula/auth`. Coming soon.


## Usage ##

```
<?php
require '/your/autoloader.php'; // composer for example

$session = new \Vespula\Auth\Session\Session();

// Optionally pass a maximum idle time and a time until the session expires (in seconds)
$max_idle = 1200;
$expire = 3600;
$session = new \Vespula\Auth\Session\Session($max_idle, $expire);

$adapter = new \Vespula\Auth\Adapter\Xyz(...); // Sql, for example

$auth = new \Vespula\Auth\Auth($adapter, $session);

if (login condition) {
    // filter/sanitize these first
    $credentials = [
        'username'=>$_POST['username'],
        'password'=>$_POST['password']
    ];

    // The credentials are passed as an array. This helps 'hide' them if an exception is thrown. Even in development environments.
    $auth->login($credentials);
    if ($auth->isValid()) {
        // Yay....
        echo "Welome " . $auth->getUsername();
        
        // Get userdata
        $userdata = $auth->getUserdata();
        echo $userdata['fullname'];

        // Shortcut to userdata
        echo $auth->getUserdata('fullname');
    } else {
        // Nay....
        // Wonder why? Any errors?
        $error = $adapter->getError(); // may be no errors. Just bad credentials
        echo "Please try again, if you dare";
    }
}

// Perform a log out
if (logout condition) {
    $auth->logout();
}

// Check if the user is valid (authenticated) 
if ($auth->isValid()) {
    // Access some part of site
}

// Has the person been sitting idle too long?
if ($auth->isIdle()) {
    // Sitting around for too long
    // User is automatically logged out and status set to ANON
}
 
// Did the expire time get reached?
// Note that if the session actually expires, this won't show as being expired.
// This is because there is no status in a non-existent session.
if ($auth->isExpired()) {
    // Sitting around way too long!
    // User is automatically logged out and status set to ANON
}
```

## Adapters ##

### Text Adapter ###

This adapter is primarily for testing purposes and should not be used in production.

```
<?php
$session = new \Vespula\Auth\Session\Session();

$adapter = new \Vespula\Auth\Adapter\Text();
$adapter->setPassword('juser', 's3cr3t_passwd');
$adapter->setUserdata('juser', [
    'fullname'=>'Joe User',
    'email'=>'juser@vespula.com'
]);

$auth = new \Vespula\Auth\Auth($adapter, $session);

if ('login button pushed logic') {
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $password = filter_input(INPUT_POST, 'password', FILTER_DEFAULT);
    $credentials = [
        'username'=>$username,
        'password'=>$password
    ];
    $auth->login($credentials);
    if ($auth->isValid()) {
        // display message, redirect, etc.
        $userdata = $auth->getUserdata();
        echo 'Hello, ' . $auth->getUsername();
        echo 'Your fullname is ' . $userdata['fullname'];
        // Or...
        echo 'Your fullname is ' . $auth->getUserdata('fullname');

    } else {
        // no luck, bad password or username
    }
}

if ('logout link clicked') {
    $auth->logout();
    // bye bye
    // $auth->isAnon() should return true
}
```

### Sql Adapter ###

Authenticate against a database table where user's passwords are stored using PHP's bcrypt hashing and the PASSWORD_DEFAULT algorithm.
Under the hood, it uses `password_verify()`.

```
// user table //
+----------+-------------+------------+---------------------+
| username | fullname    | email      | bcryptpass          |
|----------+-------------+------------+---------------------|
| juser    | Joe User    | juser@...  | $2y$.............   |
+----------+-------------+------------+---------------------+

```

```
<?php 
$session = new \Vespula\Auth\Session\Session();
$dsn = 'mysql:dbname=mydatabase;host=localhost';
$pdo = new \Pdo($dsn, 'dbuser', '********');

// $cols array must have a 'username' and 'password' element. You can use an alias if needed. See below.
$cols = [
    'username', 
    'bcryptpass'=>'password', // alias
    'fullname'=>'full_name' // alias
    'email'
];
$from = 'user';
$where = 'active=1'; // optional

$adapter = new \Vespula\Auth\Adapter\Sql($pdo, $cols, $from, $where);
$auth = new \Vespula\Auth\Auth($adapter, $session);

if ('login button pushed logic') {
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $password = filter_input(INPUT_POST, 'password', FILTER_DEFAULT);
    $credentials = [
        'username'=>$username,
        'password'=>$password
    ];
    $auth->login($credentials);
    if ($auth->isValid()) {
        // display message, redirect, etc.
        $userdata = $auth->getUserdata();
        echo 'Hello, ' . $auth->getUsername();
        echo 'Your fullname is ' . $userdata['full_name']; // note the use of the alias (not fullname)
        // Or...
        echo 'Your fullname is ' . $auth->getUserdata('fullname');
    } else {
        // no luck, bad password or username
    }
}

if ('logout link clicked') {
    $auth->logout();
    // bye bye
    // $auth->isAnon() should return true
}
```

### Ldap Adapter ###

This adapter authenticates against active directory using LDAP. If you know the DN format, you and pass that to the constructor. If you don't know it, then you can pass bind options to find the user's DN.

**Example 1: Known DN format**

```
<?php 

$session = new \Vespula\Auth\Session\Session();
$uri = 'ldap.mycompany.org'; 
$dn = 'cn=%s,OU=Users,OU=MyCompany,OU=Edmonton,OU=Alberta'; //%s replaced by username internally
$ldap_options = [
    LDAP_OPT_PROTOCOL_VERSION=>3
];

// No support for aliases yet.
$attributes = [
    'email',
    'givenname'
];

$adapter = new \Vespula\Auth\Adapter\Ldap($uri, $dn, null, $ldap_options, $attributes);
$auth = new \Vespula\Auth\Auth($adapter, $session);

if ('login button pushed logic') {
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $password = filter_input(INPUT_POST, 'password', FILTER_DEFAULT);
    $credentials = [
        'username'=>$username,
        'password'=>$password
    ];
    $auth->login($credentials);
    if ($auth->isValid()) {
        // display message, redirect, etc.
        $userdata = $auth->getUserdata();
        echo 'Hello, ' . $auth->getUsername();
        echo 'Your fullname is ' . $userdata['givenname'];
        // Or...
        echo 'Your fullname is ' . $auth->getUserdata('givenname');
    } else {
        // no luck, bad password or username
    }
}

if ('logout link clicked') {
    $auth->logout();
    // bye bye
    // $auth->isAnon() should return true
}
```

**Example 2: Unknown DN format**

```
<?php 

$session = new \Vespula\Auth\Session\Session();
$uri = 'ldap.mycompany.org';

// Specify bind options to look up the user's dn 
$bind_options = [
    'basedn'=>'OU=MyCompany,OU=Edmonton,OU=Alberta',
    'binddn'=>'cn=specialuser,OU=MyCompany,OU=Edmonton,OU=Alberta',
    'bindpw'=>'********',
    'filter'=>'samaccountname=%s' // what do we use to find the person in Active Directory?
];
$ldap_options = [
    LDAP_OPT_PROTOCOL_VERSION=>3
];

// No support for aliases yet.
$attributes = [
    'email',
    'givenname'
];

$adapter = new \Vespula\Auth\Adapter\Ldap($uri, null, $bind_options, $ldap_options, $attributes);
$auth = new \Vespula\Auth\Auth($adapter, $session);

if ('login button pushed logic') {
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $password = filter_input(INPUT_POST, 'password', FILTER_DEFAULT);
    $credentials = [
        'username'=>$username,
        'password'=>$password
    ];
    $auth->login($credentials);
    if ($auth->isValid()) {
        // display message, redirect, etc.
        $userdata = $auth->getUserdata();
        echo 'Hello, ' . $auth->getUsername();
        echo 'Your fullname is ' . $userdata['givenname'];
        // Or...
        echo 'Your fullname is ' . $auth->getUserdata('givenname');
    } else {
        // no luck, bad password or username
    }
}

if ('logout link clicked') {
    $auth->logout();
    // bye bye
    // $auth->isAnon() should return true
}
```