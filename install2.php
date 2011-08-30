<?php
session_start();

define('DEBUG', FALSE);
if (DEBUG) {
	error_reporting(E_ALL);
}

define('INSTALLER_VERSION', '1.00');
define('INSTALLER_FILE', basename(__FILE__));

define('PRODUCT_NAME', 'Quick Homepage Maker Professional');
define('PRODUCT_JNAME', 'QHMプロ');
define('PRODUCT_CODENAME', 'qhmpro');
define('PRODUCT_INSTALL_SYSTEM', 'https://ensmall.net/p/qhmpro/sys/');

define('PRODUCT_CONFIG_FILE', 'qhm.ini.php');
define('PRODUCT_CHECK_FILE', 'pukiwiki.ini.php');
define('PRODUCT_VERSION_FILE', 'lib/init.php');

define('DESCRIPTION_FILE', 'QHMProfessional.txt');//利用規約ファイル

define('ALLOW_PASSWD_PATTERN', "/^[!-~]+$/");
define('ALLOW_PASSWD_NUM', 6);

define('ENSMALL_SSL', 'https://ensmall.net/');
$scheme = 'http';
if ((intval(phpversion()) > 4) && function_exists('stream_get_wrappers') && in_array('https', stream_get_wrappers()))
{
	if ($fp = fopen(ENSMALL_SSL, 'r'))
	{
		fclose($fp);
		$scheme = 'https';
	}
}
define('ENSMALL_CLUB_HTTP_SCHEME', $scheme);
define('ENSMALL_CLUB_URL',    ENSMALL_CLUB_HTTP_SCHEME. '://ensmall.net/club_dev/');
define('ENSMALL_PRODUCT_URL', ENSMALL_CLUB_HTTP_SCHEME. '://ensmall.net/hkn_p/');

define('ENSMALL_STATUS_SUCCESS', 101);
define('ENSMALL_STATUS_ERROR', 200);
define('ENSMALL_STATUS_ERROR_NO_USER', 201);
define('ENSMALL_STATUS_ERROR_NO_PRODUCT', 202);
define('ENSMALL_STATUS_ERROR_INSTALL_OVER', 203);


/**
* PukiWiki lib/proxy.phpを参考に作った(GPLライセンスになるか？）
* 
* 使い方)
* $res = http_req('http://ensmall.net/dev/k/ba/', $params);
* echo $res['data'];
*
* $res['query'] --- HTTPリクエストヘッダー
* $res['rc']    --- HTTPレスポンスヘッダー
* $res['data']  --- コンテンツ
*
* POSTする場合:
*  $params = array('method'=>'POST', 'post'=>array('key1'=>'value1', 'key2'=>'value2'));
*  $res = http_req('http://ensmall.net/dev/k/ba/', $params);
*
* Basic認証:
*  $res = http_req('http://user:pass@hogehgoe.net/');
*
* Proxy経由:
*  $res = http_req('http://hogehoge.net/', array('proxy_host'=>'proxy.hoge.ne.jp:8080'));
*
*/

// -------------------------
// Sample Script
//
// 通常のアクセス(GET)
//$res = http_req('http://hokuken.xsrv.jp/');
//
// GETアクセス
//$res = http_req('http://hokuken.xsrv.jp/index.php?key1=value1&key2=value2');
//
// POSTアクセス
//$params = array(
//	'method' => 'POST',
//	'post'   => array('key1'=>'val1', 'key2'=>'val2'),
//);
//$res = http_req('http://hokuken.xsrv.jp/', $params);
//
//echo $res['data'];


function http_req($url, $params=array())
{

	//init params
	$config = array(
		'method'  	=> 'GET', // or POST
		'headers' 	=> '', 
		'post' 	  	=> array(),  // array('key1'=>'value1', 'key2'=>'value2' ...);
		'redirect_max'		=> 2,  // retry
		'content_charset' 	=> '',
		'ua' 		=> 'PHPScript',
		'proxy_host'=> '',
		'no_proxy'	=> array('localhost', '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'no-proxy.com'),
		'use_proxy' => FALSE,
		'proxy_port' => '',
		'need_proxy_auth' => 'FALSE',
		'proxy_auth_user' => '',
		'proxy_auth_pass' => ''
	);
	
	//update 
	foreach($config as $key=>$val)
	{
		if(isset($params[$key]))
		{
			$config[$key] = $params[$key];
		}
	}
	
	//make local values
	extract($config);
	
	if($proxy_host != '')
	{
		if(!preg_match('#^[a-z]+://#', $proxy_host))
		{
			$proxy_host = 'http://'.$proxy_host;
		}
		$proxy_params = parse_url($proxy_host);

		$proxy_host = $proxy_params['host'];
		$use_proxy = TRUE;
		$proxy_port = isset($proxy_params['port']) ? $proxy_params['port'] : '8080';
		$need_proxy_auth = isset($proxy_params['user']);
		$proxy_auth_user = isset($proxy_params['user']) ? $proxy_params['user'] : '';
		$proxy_auth_pass = isset($proxy_params['pass']) ? $proxy_params['pass'] : '';
		
	}
	
//	var_dump($method, $headers, $post, $redirect_max, $content_charset, $ua);
//	var_dump($proxy_host, $use_proxy, $proxy_port, $need_proxy_auth, $proxy_auth_user, $proxy_auth_pass);


	$rc  = array();
	$arr = parse_url($url);

	$via_proxy = $use_proxy ? ! in_the_net($no_proxy, $arr['host']) : FALSE;

	// query
	$arr['query'] = isset($arr['query']) ? '?' . $arr['query'] : '';
	// port
	$arr['port']  = isset($arr['port'])  ? $arr['port'] : 80;

	$url_base = $arr['scheme'] . '://' . $arr['host'] . ':' . $arr['port'];
	$url_path = isset($arr['path']) ? $arr['path'] : '/';
	$url = ($via_proxy ? $url_base : '') . $url_path . $arr['query'];

	$query = $method . ' ' . $url . ' HTTP/1.0' . "\r\n";
	$query .= 'Host: ' . $arr['host'] . "\r\n";
	$query .= 'User-Agent: '. $ua . "\r\n";

	// Basic-auth for HTTP proxy server
	if ($need_proxy_auth && isset($proxy_auth_user) && isset($proxy_auth_pass))
		$query .= 'Proxy-Authorization: Basic '.
			base64_encode($proxy_auth_user . ':' . $proxy_auth_pass) . "\r\n";

	// (Normal) Basic-auth for remote host
	if (isset($arr['user']) && isset($arr['pass']))
		$query .= 'Authorization: Basic '.
			base64_encode($arr['user'] . ':' . $arr['pass']) . "\r\n";

	$query .= $headers;

	if (strtoupper($method) == 'POST') {
		// 'application/x-www-form-urlencoded', especially for TrackBack ping
		$POST = array();
		foreach ($post as $name=>$val) $POST[] = $name . '=' . urlencode($val);
		$data = join('&', $POST);

		if (preg_match('/^[a-zA-Z0-9_-]+$/', $content_charset)) {
			// Legacy but simple
			$query .= 'Content-Type: application/x-www-form-urlencoded' . "\r\n";
		} else {
			// With charset (NOTE: Some implementation may hate this)
			$query .= 'Content-Type: application/x-www-form-urlencoded' .
				'; charset=' . strtolower($content_charset) . "\r\n";
		}

		$query .= 'Content-Length: ' . strlen($data) . "\r\n";
		$query .= "\r\n";
		$query .= $data;
	} else {
		$query .= "\r\n";
	}

	$errno  = 0;
	$errstr = '';
	$fp = fsockopen(
		$via_proxy ? $proxy_host : $arr['host'],
		$via_proxy ? $proxy_port : $arr['port'],
		$errno, $errstr, 30);
	if ($fp === FALSE) {
		return array(
			'query'  => $query, // Query string
			'rc'     => $errno, // Error number
			'header' => '',     // Header
			'data'   => $errstr // Error message
		);
	}
	fputs($fp, $query);
	$response = '';
	while (! feof($fp)) $response .= fread($fp, 4096);
	fclose($fp);

	$resp = explode("\r\n\r\n", $response, 2);
	$rccd = explode(' ', $resp[0], 3); // array('HTTP/1.1', '200', 'OK\r\n...')
	$rc   = (integer)$rccd[1];

	switch ($rc) {
	case 301: // Moved Permanently
	case 302: // Moved Temporarily
		$matches = array();
		if (preg_match('/^Location: (.+)$/m', $resp[0], $matches)
			&& --$redirect_max > 0)
		{
			$url = trim($matches[1]);
			if (! preg_match('/^https?:\//', $url)) {
				// Relative path to Absolute
				if ($url{0} != '/')
					$url = substr($url_path, 0, strrpos($url_path, '/')) . '/' . $url;
				$url = $url_base . $url; // Add sheme, host
			}
			// Redirect
			return http_request($url, $method, $headers, $post, $redirect_max);
		}
	}
	return array(
		'query'  => $query,   // Query String
		'rc'     => $rc,      // Response Code
		'header' => $resp[0], // Header
		'data'   => $resp[1]  // Data
	);
}

// Separate IPv4 network-address and its netmask
// Check if the $host is in the specified network(s)
function in_the_net($networks = array(), $host = '')
{
	$cidr_nw_regex = '/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\/([0-9.]+))?$/';
	
	if (empty($networks) || $host == '') return FALSE;
	if (! is_array($networks)) $networks = array($networks);

	$matches = array();

	if (preg_match($cidr_nw_regex, $host, $matches)) {
		$ip = $matches[1];
	} else {
		$ip = gethostbyname($host); // May heavy
	}
	$l_ip = ip2long($ip);

	foreach ($networks as $network) {
		if (preg_match($cidr_nw_regex, $network, $matches) &&
		    is_long($l_ip) && long2ip($l_ip) == $ip) {
			// $host seems valid IPv4 address
			// Sample: '10.0.0.0/8' or '10.0.0.0/255.0.0.0'
			$l_net = ip2long($matches[1]); // '10.0.0.0'
			$mask  = isset($matches[2]) ? $matches[2] : 32; // '8' or '255.0.0.0'
			$mask  = is_numeric($mask) ?
				pow(2, 32) - pow(2, 32 - $mask) : // '8' means '8-bit mask'
				ip2long($mask);                   // '255.0.0.0' (the same)

			if (($l_ip & $mask) == $l_net) return TRUE;
		} else {
			// $host seems not IPv4 address. May be a DNS name like 'foobar.example.com'?
			foreach ($networks as $network)
				if (preg_match('/\.?\b' . preg_quote($network, '/') . '$/', $host))
					return TRUE;
		}
	}

	return FALSE; // Not found
}


function input_filter($param)
{
        static $magic_quotes_gpc = NULL;
        if ($magic_quotes_gpc === NULL)
            $magic_quotes_gpc = get_magic_quotes_gpc();

        if (is_array($param)) {
                return array_map('input_filter', $param);
        } else {
                $result = str_replace("\0", '', $param);
                if ($magic_quotes_gpc) $result = stripslashes($result);
                return $result;
        }
}

function h($str){
	return htmlspecialchars($str, ENT_QUOTES);
}
/**
* ORMcrypt class
*
* Blowfishを使って暗号化するためのクラス。簡単に使える。
* 使い方は以下の通り。
*
* 
<code>

//暗号キーを使ってインスタンスを生成
$mc = new ORMcrypt('hogehoge');

//暗号化すると、配列で暗号データが戻る（両方とも復号に必要）
// $arr[0]は、本文の暗号化データ。$arr[1]は、復号に必要な初期ブロック値
$arr = $mc->encrypt('こんにちは！こんにちは！世界の国から〜♪');
var_dump($arr);

//複合化する。先のセットのデータを渡す
$data = $mc->decrypt($arr[0], $arr[1]);
var_dump($data);

//パスワードのストレッチングをするためのクラスメソッド
var_dump( sha1('passwd'), ORMcrypt::stretching('passwd') );

</code>

*
* @package ORIGAMI
*
*
*/
class ORMcrypt{
	
	// get_key を使って適宜変更
	private $key = 'IK8l6xXw1fYMEHGKjNFC64NoAexzJlkzQJUX4Y';
	
	//この値を変えると、ivデータの暗号化のiv文字列を変えられ、セキュリティーを高められますが、変えなくてもOK
	private static $iviv_seed = '9ijhtr4';
	
	private $_mcrypt_exists;
	
	private $cipher;
	private $mode;
	private $iv_size;
	private $dummy_iv;

	// --------------------------------------------------------------------
	
	/**
	* 暗号、復号を行うオブジェクトを生成
	*
	* @param string 暗号用キー
	*/
	function __construct($key = '')
	{
		if (strlen($key) > 0)
		{
			$this->key = $key;
		}

		$this->_mcrypt_exists = ( ! function_exists('mcrypt_encrypt')) ? FALSE : TRUE;
		
		if( $this->_mcrypt_exists )
		{
			$this->cipher   = MCRYPT_BLOWFISH;
			$this->mode     = MCRYPT_MODE_CBC;
			$this->iv_size  = mcrypt_get_iv_size($this->cipher, $this->mode);
			$this->dummy_iv = str_pad('', $this->iv_size, self::$iviv_seed);
		}
	}

	// --------------------------------------------------------------------

	/**
	* データを暗号化し、base64化した暗号データを返す。返される値は、配列になっており、復号には両方必要。
	* 一つ目が$data、二つ目が復号に必要な初期ブロック値の暗号データ。
	* 
	* @param string
	* @return array
	*/
	function encrypt($data)
	{
		if( $this->_mcrypt_exists )
		{
			$iv_size = $this->iv_size;
			
			srand(); //windows ready
			$iv      = mcrypt_create_iv($iv_size, MCRYPT_DEV_RANDOM);
			$crypt_msg = mcrypt_encrypt($this->cipher, $this->key, base64_encode($data),  $this->mode, $iv);
			$crypt_iv  = mcrypt_encrypt($this->cipher, $this->key, base64_encode($iv),  $this->mode, $this->dummy_iv);
			return array( base64_encode($crypt_msg), base64_encode($crypt_iv) );
		}
		else // XOR Encrypt
		{
			return array( base64_encode($this->_xor_encode($data, $this->key)), '');
		}
	}

	// --------------------------------------------------------------------
	
	/**
	* データを複合化する
	*
	* @param string
	* @param string
	* @return string
	*/
	function decrypt($crypt_data, $crypt_iv)
	{
		if( $this->_mcrypt_exists )
		{
			$iv =  $this->_mdecrypt( base64_decode($crypt_iv), $this->dummy_iv);
			$data = $this->_mdecrypt( base64_decode($crypt_data), $iv);
			
			return $data;
		}
		else // XOR Decrypt
		{
			return $this->_xor_decode( base64_decode($crypt_data), $this->key);
		}
	}

	// --------------------------------------------------------------------
	
	function _mdecrypt($data, $iv)
	{
		return base64_decode(
			rtrim( mcrypt_decrypt($this->cipher, $this->key, $data, $this->mode, $iv), "\0" )
		);	
	}
	
	// --------------------------------------------------------------------

	/**
	 * XOR Encode
	 *
	 * Takes a plain-text string and key as input and generates an
	 * encoded bit-string using XOR
	 *
	 * @access	private
	 * @param	string
	 * @param	string
	 * @return	string
	 */
	function _xor_encode($string, $key)
	{
		$rand = '';
		while (strlen($rand) < 32)
		{
			$rand .= mt_rand(0, mt_getrandmax());
		}

		$rand = sha1($rand);

		$enc = '';
		for ($i = 0; $i < strlen($string); $i++)
		{
			$enc .= substr($rand, ($i % strlen($rand)), 1).(substr($rand, ($i % strlen($rand)), 1) ^ substr($string, $i, 1));
		}

		return $this->_xor_merge($enc, $key);
	}

	// --------------------------------------------------------------------

	/**
	 * XOR Decode
	 *
	 * Takes an encoded string and key as input and generates the
	 * plain-text original message
	 *
	 * @access	private
	 * @param	string
	 * @param	string
	 * @return	string
	 */
	function _xor_decode($string, $key)
	{
		$string = $this->_xor_merge($string, $key);

		$dec = '';
		for ($i = 0; $i < strlen($string); $i++)
		{
			$dec .= (substr($string, $i++, 1) ^ substr($string, $i, 1));
		}

		return $dec;
	}

	// --------------------------------------------------------------------

	/**
	 * XOR key + string Combiner
	 *
	 * Takes a string and key as input and computes the difference using XOR
	 *
	 * @access	private
	 * @param	string
	 * @param	string
	 * @return	string
	 */
	function _xor_merge($string, $key)
	{
		$hash = sha1($key);
		$str = '';
		for ($i = 0; $i < strlen($string); $i++)
		{
			$str .= substr($string, $i, 1) ^ substr($hash, ($i % strlen($hash)), 1);
		}

		return $str;
	}

	// --------------------------------------------------------------------
	
	/**
	* パスワードをストレッチングするためのお助け関数
	*/
	static public function stretching($password, $sec_salt = null)
	{
		if($sec_salt == null)
		{
			$seed = self::$iviv_seed;
			$sec_salt = str_pad($seed, 64,  $seed);
		}
		
		$hash = '';
		for($i=0; $i<1000; $i++){
			$hash = sha1($hash.$password.$sec_salt);
		}
		
		return $hash;
	}

	// --------------------------------------------------------------------
	
	/**
	* ランダムなキーを作成するためのお助け関数
	*/
	static public function get_key($num = 40)
	{
		$str = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';
		$max = strlen($str);

		$key = '';
		for ($i=0; $i < $num; $i++)
		{
			$key .= substr( $str, mt_rand(0, $max) , 1);
		}
		
		return $key;
	}
}
/**
 * CodeIgniter
 *
 * An open source application development framework for PHP 4.3.2 or newer
 *
 * @package		HKNTool
 * @author		ExpressionEngine Dev Team
 * @copyright	Copyright (c) 2008, EllisLab, Inc.
 * @license		http://codeigniter.com/user_guide/license.html
 * @link		http://codeigniter.com
 * @since		Version 1.0
 * @filesource
 *
 *
 *
 *  hokuken.com customizing history
 *  ---------------------------------
 *	
 *  version 1.1  2010 2/3
 *
 *  is_existsメソッドの追加。ファイルのありなしを返す。0なら、存在しない。1ならファイル、それ以上ならディレクトリ。
 *  list_filesメソッドの戻り値（ファイル群のリスト）を、絶対パス付きに変更（ ftp_pwd()の結果を付ける ）
 *    また、list_filesの引数に 絶対パス指定の場合は、そのまま出力するように変更。
 *
 */
 
// ------------------------------------------------------------------------

/**
 * FTP Class
 *
 * @package		HKNTool
 * @subpackage	Libraries
 * @category	Libraries
 * @author		ExpressionEngine Dev Team
 * @link		http://codeigniter.com/user_guide/libraries/ftp.html
 */
class CI_FTP {

	var $hostname	= '';
	var $username	= '';
	var $password	= '';
	var $port		= 21;
	var $passive	= TRUE;
	var $debug		= FALSE;
	var $conn_id	= FALSE;
	var $all_binary = TRUE;
	
	var $debug_msg  = array();

	/**
	 * Constructor - Sets Preferences
	 *
	 * The constructor can be passed an array of config values
	 */
	function CI_FTP($config = array())
	{
		if (count($config) > 0)
		{
			$this->initialize($config);
		}

//		log_message('debug', "FTP Class Initialized");
	}

	// --------------------------------------------------------------------

	/**
	 * Initialize preferences
	 *
	 * @access	public
	 * @param	array
	 * @return	void
	 */
	function initialize($config = array())
	{
		foreach ($config as $key => $val)
		{
			if (isset($this->$key))
			{
				$this->$key = $val;
			}
		}

		// Prep the hostname
		$this->hostname = preg_replace('|.+?://|', '', $this->hostname);
	}

	// --------------------------------------------------------------------

	/**
	 * FTP Connect
	 *
	 * @access	public
	 * @param	array	 the connection values
	 * @return	bool
	 */
	function connect($config = array())
	{
		if (count($config) > 0)
		{
			$this->initialize($config);
		}

//		if (FALSE === ($this->conn_id = @ftp_connect($this->hostname, $this->port)))
		if (FALSE === ($this->conn_id = @ftp_ssl_connect($this->hostname, $this->port)))
		{
			if ($this->debug == TRUE)
			{
				$this->_error('ftp_unable_to_connect');
			}
			return FALSE;
		}

		if ( ! $this->_login())
		{
			if ($this->debug == TRUE)
			{
				$this->_error('ftp_unable_to_login');
			}
			return FALSE;
		}

		// Set passive mode if needed
		if ($this->passive == TRUE)
		{
			ftp_pasv($this->conn_id, TRUE);
		}

		return TRUE;
	}

	// --------------------------------------------------------------------

	/**
	 * FTP Login
	 *
	 * @access	private
	 * @return	bool
	 */
	function _login()
	{
		return @ftp_login($this->conn_id, $this->username, $this->password);
	}

	// --------------------------------------------------------------------

	/**
	 * Validates the connection ID
	 *
	 * @access	private
	 * @return	bool
	 */
	function _is_conn()
	{
		if ( ! is_resource($this->conn_id))
		{
			if ($this->debug == TRUE)
			{
				$this->_error('ftp_no_connection');
			}
			return FALSE;
		}
		return TRUE;
	}

	// --------------------------------------------------------------------


	/**
	 * Change direcotry
	 *
	 * The second parameter lets us momentarily turn off debugging so that
	 * this function can be used to test for the existance of a folder
	 * without throwing an error.  There's no FTP equivalent to is_dir()
	 * so we do it by trying to change to a particular directory.
	 * Internally, this paramter is only used by the "mirror" function below.
	 *
	 * @access	public
	 * @param	string
	 * @param	bool
	 * @return	bool
	 */
	function changedir($path = '', $supress_debug = FALSE)
	{
		if ($path == '' OR ! $this->_is_conn())
		{
			return FALSE;
		}

		$result = @ftp_chdir($this->conn_id, $path);

		if ($result === FALSE)
		{
			if ($this->debug == TRUE AND $supress_debug == FALSE)
			{
				$this->_error('ftp_unable_to_changedir');
			}
			return FALSE;
		}

		return TRUE;
	}

	// --------------------------------------------------------------------

	/**
	 * Create a directory
	 *
	 * @access	public
	 * @param	string
	 * @return	bool
	 */
	function mkdir($path = '', $permissions = NULL)
	{
		if ($path == '' OR ! $this->_is_conn())
		{
			return FALSE;
		}

		$result = @ftp_mkdir($this->conn_id, $path);

		if ($result === FALSE)
		{
			if ($this->debug == TRUE)
			{
				$this->_error('ftp_unable_to_makdir : '.$path);
			}
			return FALSE;
		}

		// Set file permissions if needed
		if ( ! is_null($permissions))
		{
			$this->chmod($path, (int)$permissions);
		}

		return TRUE;
	}

	// --------------------------------------------------------------------

	/**
	 * Upload a file to the server
	 *
	 * @access	public
	 * @param	string
	 * @param	string
	 * @param	string
	 * @return	bool
	 */
	function upload($locpath, $rempath, $mode = 'auto', $permissions = NULL)
	{
		if ( ! $this->_is_conn())
		{
			return FALSE;
		}

		if ( ! file_exists($locpath))
		{
			$this->_error('ftp_no_source_file');
			return FALSE;
		}

		// Set the mode if not specified
		if ($mode == 'auto')
		{
			// Get the file extension so we can set the upload type
			$ext = $this->_getext($locpath);
			$mode = $this->_settype($ext);
		}

		$mode = ($mode == 'ascii') ? FTP_ASCII : FTP_BINARY;
		$result = @ftp_put($this->conn_id, $rempath, $locpath, $mode);

		if ($result === FALSE)
		{
			if ($this->debug == TRUE)
			{
				$this->_error('ftp_unable_to_upload : '.$locpath);
			}
			return FALSE;
		}

		// Set file permissions if needed
		if ( ! is_null($permissions))
		{
			$this->chmod($rempath, (int)$permissions);
		}

		return TRUE;
	}
	
	function download($locpath, $rempath, $mode = 'auto')
	{
		if ( ! $this->_is_conn())
		{
			return FALSE;
		}
		
		// Set the mode if not specified
		if ($mode == 'auto')
		{
			// Get the file extension so we can set the upload type
			$ext = $this->_getext($locpath);
			$mode = $this->_settype($ext);
		}

		$mode = ($mode == 'ascii') ? FTP_ASCII : FTP_BINARY;
		$result = @ftp_get($this->conn_id, $locpath, $rempath, $mode);
		if ($result === FALSE)
		{
			if ($this->debug == TRUE)
			{
				$this->_error('ftp_unable_to_download : '.$rempath.' --> '.$locpath);
			}
			return FALSE;
		}
		return TRUE;
	}

	// --------------------------------------------------------------------

	/**
	 * Rename (or move) a file
	 *
	 * @access	public
	 * @param	string
	 * @param	string
	 * @param	bool
	 * @return	bool
	 */
	function rename($old_file, $new_file, $move = FALSE)
	{
		if ( ! $this->_is_conn())
		{
			return FALSE;
		}

		$result = @ftp_rename($this->conn_id, $old_file, $new_file);

		if ($result === FALSE)
		{
			if ($this->debug == TRUE)
			{
				$msg = ($move == FALSE) ? 'ftp_unable_to_rename' : 'ftp_unable_to_move';

				$this->_error($msg);
			}
			return FALSE;
		}

		return TRUE;
	}

	// --------------------------------------------------------------------

	/**
	 * Move a file
	 *
	 * @access	public
	 * @param	string
	 * @param	string
	 * @return	bool
	 */
	function move($old_file, $new_file)
	{
		return $this->rename($old_file, $new_file, TRUE);
	}

	// --------------------------------------------------------------------

	/**
	 * Rename (or move) a file
	 *
	 * @access	public
	 * @param	string
	 * @return	bool
	 */
	function delete_file($filepath)
	{
		if ( ! $this->_is_conn())
		{
			return FALSE;
		}

		$result = @ftp_delete($this->conn_id, $filepath);

		if ($result === FALSE)
		{
			if ($this->debug == TRUE)
			{
				$this->_error('ftp_unable_to_delete : '.$filepath);
			}
			return FALSE;
		}

		return TRUE;
	}

	// --------------------------------------------------------------------

	/**
	 * Delete a folder and recursively delete everything (including sub-folders)
	 * containted within it.
	 *
	 * @access	public
	 * @param	string
	 * @return	bool
	 */
	function delete_dir($filepath)
	{

		if ( ! $this->_is_conn())
		{
			return FALSE;
		}

		// Add a trailing slash to the file path if needed
		$filepath = preg_replace("/(.+?)\/*$/", "\\1/",  $filepath);
		$list = $this->list_files($filepath);

		if ($list !== FALSE AND count($list) > 0)
		{
			foreach ($list as $item)
			{
				$bname = basename($item); //for servers likes lolipop
				// If we can't delete the item it's probaly a folder so
				// we'll recursively call delete_dir()	
				if ( !preg_match('/\.$/',$bname) )
				{
					$deleted = @ftp_delete($this->conn_id, $item);
					
					if(! $deleted)
					{
						$this->delete_dir($item);
					}
				}
			}
		}
		
		$result = @ftp_rmdir($this->conn_id, $filepath);

		if ($result === FALSE)
		{
			if ($this->debug == TRUE)
			{
				$this->_error('ftp_unable_to_delete');
			}
			return FALSE;
		}

		return TRUE;
	}


	// --------------------------------------------------------------------

	/**
	 * Set file permissions
	 *
	 * @access	public
	 * @param	string 	the file path
	 * @param	string	the permissions
	 * @return	bool
	 */
	function chmod($path, $perm)
	{
		if ( ! $this->_is_conn())
		{
			return FALSE;
		}

		// Permissions can only be set when running PHP 5
		if ( ! function_exists('ftp_chmod'))
		{
			if ($this->debug == TRUE)
			{
				$this->_error('ftp_unable_to_chmod');
			}
			return FALSE;
		}

		$result = @ftp_chmod($this->conn_id, $perm, $path);

		if ($result === FALSE)
		{
			if ($this->debug == TRUE)
			{
				$this->_error('ftp_unable_to_chmod');
			}
			return FALSE;
		}

		return TRUE;
	}

	// --------------------------------------------------------------------

	/**
	 * FTP List files in the specified directory
	 * 
	 * Caution: nlist option '-a' for hidden files (.htaccess, .htpasswd)
	 *    and @ftp_chdir(connid, path) is for sakura server.
	 *    Because, sakura server returned not NULL but "No such file ..." if 
	 *    path is not exists.
	 * 
	 *  ftp_pwd()の結果を付属したリストを返す（つまり、絶対パスで返す）。
	 *  これは、サーバーによって ftp_nlistの出力がパス付きだったり、そうでなかったりするから。
	 * 
	 * @param string $path
	 * @param string $option ftp_nlist に渡すコマンドのパス
	 * @access	public
	 * @return	array
	 */
	function list_files($path = '.', $option = '-a ')
	{
		if ( ! $this->_is_conn())
		{
			return FALSE;
		}

		if( $path{0} != '/'){
			$pwd = ftp_pwd($this->conn_id).'/';
		}
		else{
			$pwd = '';
		}

		$path .= preg_match('/\/$/',$path) ? '' : '/';
		
		if( ftp_chdir($this->conn_id, $path) ){
			ftp_chdir($this->conn_id, $pwd) or user_error("Can't return parent director.");
			$list = ftp_nlist($this->conn_id, $option.$path);
		}
		else{
			$path = rtrim($path, '/');
			$list = ftp_nlist($this->conn_id, $option.$path);
		}

		foreach($list as $k=>$v){
			$fname = basename($v);
			$list[$k] = $pwd.$path.$fname;
		}
		return $list;
	}
	
	function is_dir($path)
	{
		if ( ! $this->_is_conn())
		{
			return FALSE;
		}

		$pwd = ftp_pwd($this->conn_id);

		if( ftp_chdir($this->conn_id, $path) ){
			ftp_chdir($this->conn_id, $pwd) or user_error("Can't return parent director.");
			return TRUE;
		}
		else{
			return FALSE;
		}
	}
	
	function is_exists($path){
		if ( ! $this->_is_conn())
		{
			return FALSE;
		}
		
		//新バージョン
		
		if( $this->is_dir($path) ){
			return true;
		}
		
		$list = $this->list_files($path, '');
		if (is_array($list) && count($list)) {
			return true;
		} else {
			return false;
		}
	}

	// ------------------------------------------------------------------------

	/**
	 * Read a directory and recreate it remotely
	 *
	 * This function recursively reads a folder and everything it contains (including
	 * sub-folders) and creates a mirror via FTP based on it.  Whatever the directory structure
	 * of the original file path will be recreated on the server.
	 *
	 * @access	public
	 * @param	string	path to source with trailing slash
	 * @param	string	path to destination - include the base folder with trailing slash
	 * @return	bool
	 */
	function mirror($locpath, $rempath)
	{
		if ( ! $this->_is_conn())
		{
			return FALSE;
		}

		// Open the local file path
		if ($fp = @opendir($locpath))
		{
			// Attempt to open the remote file path.
			if ( ! $this->changedir($rempath, TRUE))
			{
				// If it doesn't exist we'll attempt to create the direcotory
				if ( ! $this->mkdir($rempath) OR ! $this->changedir($rempath))
				{
					return FALSE;
				}
			}

			// Recursively read the local directory
			while (FALSE !== ($file = readdir($fp)))
			{
				if (@is_dir($locpath.$file) && substr($file, 0, 1) != '.')
				{
					$this->mirror($locpath.$file."/", $rempath.$file."/");
				}
				elseif ($file != "." && $file != "..")
				{
					// Get the file extension so we can se the upload type
					$ext = $this->_getext($file);
					$mode = $this->_settype($ext);

					$this->upload($locpath.$file, $rempath.$file, $mode);
				}
			}
			return TRUE;
		}

		return FALSE;
	}


	// --------------------------------------------------------------------

	/**
	 * Extract the file extension
	 *
	 * @access	private
	 * @param	string
	 * @return	string
	 */
	function _getext($filename)
	{
		if (FALSE === strpos($filename, '.'))
		{
			return 'txt';
		}

		$x = explode('.', $filename);
		return end($x);
	}


	// --------------------------------------------------------------------

	/**
	 * Set the upload type
	 *
	 * @access	private
	 * @param	string
	 * @return	string
	 */
	function _settype($ext)
	{

		if($this->all_binary){
			return 'binary';
		}

		$text_types = array(
							'txt',
							'text',
							'php',
							'phps',
							'php4',
							'js',
							'css',
							'htm',
							'html',
							'phtml',
							'shtml',
							'log',
							'xml',
							);


		return (in_array($ext, $text_types)) ? 'ascii' : 'binary';
	}

	// ------------------------------------------------------------------------

	/**
	 * Close the connection
	 *
	 * @access	public
	 * @param	string	path to source
	 * @param	string	path to destination
	 * @return	bool
	 */
	function close()
	{
		if ( ! $this->_is_conn())
		{
			return FALSE;
		}

		@ftp_close($this->conn_id);
	}

	// ------------------------------------------------------------------------

	/**
	 * Display error message
	 *
	 * @access	private
	 * @param	string
	 * @return	bool
	 */
	function _error($line)
	{
		echo $line."\n";
	}
	
	function pwd()
	{
		if ( ! $this->_is_conn())
		{
			return FALSE;
		}

		return @ftp_pwd($this->conn_id);
	}

}
// END FTP Class

/* End of file Ftp.php */
/* Location: ./system/libraries/Ftp.php */
/**
 *   Hokuken FTP class
 *   -------------------------------------------
 *   HKNFtp.php
 *   
 *   Copyright (c) 2010 hokuken
 *   http://hokuken.com/
 *   
 *   created  : 2010-03-17
 *   modified : 2010-11-05 利用規約を設置するよう変更
 *   
 *   @package		HKNTool
 *
 *
 *   北研商品全般に使える予定
 *   
 *   Usage :
 *     必ず ../config.php を読み込むこと。
 *
 *   TODO: commu/sys/lib/ のHKNFtp と統合する
 */
class HKN_FTP extends CI_FTP {

	var $ftps;
	var $classname = 'HKN_FTP';

	/** 製品名 */
	var $pname = '';
	/** 製品マスター格納フォルダ */
	var $masterDir;
	/** レストアフォルダチェックファイル */
	var $indicator = 'index.php';
	/** 利用規約を保存するファイル名 */
	var $description_file;

	/** インストールフォルダ */
	var $dir;
	/** チェック用URL */
	var $url;
	/** 製品バージョン */
	var $version;
	/** 開発リビジョン */
	var $revision;
	
	/** FTP ホストが存在するかどうか*/
	var $isConnectable;
	/** FTP ログインできるかどうか */
	var $isAuthentic;
	/** 書き込み権限があるかどうか */
	var $isWritable;
	/** PHP version */
	var $phpversion;
	/** フォルダが存在するかどうか*/
	var $existInstallDir;
	
	/** エラーメッセージ */
	var $errmsg = '';
	/** 警告メッセージ配列 */
	var $warnings = array();
	/** サーバー情報 */
	var $server;
	/** ログインフォルダ */
	var $loginroot;
	
	
	/** file 配列 */
	var $files = array();
	/** update file 配列 */
	var $updates = array();
	/** constant file 配列 */
	var $consts = array();
	/** Plugin 配列: {pluginname: boolean $installed} */
	var $plugins = array();
	/** Plugin file 配列: {pluginname: array $files} */
	var $pluginFiles = array();
	/** ログを書かないフラグ */
	var $skipLog = FALSE;
	/** index.html をリネームするフラグ */
	var $mv_index = FALSE;
	
	/** getProps() で取得できない非公開プロパティ */
	var $priProps = array(
		'errmsg', 'r_fname', 'priProps', 'pname', 'masterDir', 'files', 'updates', 'consts', 'pluginFiles', 'skipLog', 'mv_index'
	);

	/**
	 *   初期化
	 *
	 *   フィールドなどセットする。
	 */
	function initialize($config = array()) {
		foreach ($config as $key => $val)
		{
			if (property_exists($this->classname, $key))
			{
				$this->$key = $val;
			}
		}
	}
	
	/**
	 *   プロパティを取得する
	 *
	 *   必要なプロパティだけ取得する
	 */
	function getProps() {
		$priprs = $this->priProps;

		$vars = get_object_vars($this);
		$retvars = array();
		foreach ($vars as $key => $var) {
			if (!in_array($key, $priprs)) {
				$retvars[$key] = $var;
			}
		}
		return $retvars;
	}
	/**
	 *   プロパティをセットする
	 */
	function setProps($props) {
		foreach ($props as $key => $prop) {
			if (!in_array($key, $this->priProps) && property_exists(__CLASS__, $key)) {
				$this->$key = $prop;
			}
		}
	}

	/**
	 *   プロパティをセッションにセットする
	 */
	function saveProps() {
		if (!defined("PRODUCT_CODENAME"))
			return FALSE;

		$_SESSION['ftp_info'] = $this->getProps();
	}
	
	/**
	 *   プロパティをセッションから読み込む
	 */
	function readProps()
	{
		if (!isset($_SESSION) || !isset($_SESSION['ftp_info']) ) {
			return FALSE;
		}
		
		$this->setProps($_SESSION['ftp_info']);
	
	}

	/**
	 *   FTP接続し、エラーメッセージを格納する
	 *   @override
	 */
	function connect($config = array())
	{
		if (count($config) > 0)
		{
			$this->initialize($config);
		}
		
		if (($result = $this->conn_id = @ftp_ssl_connect($this->hostname, $this->port)) === FALSE)
		{
			$result = $this->conn_id = @ftp_connect($this->hostname, $this->port);
		}
		else {
			$this->ftps = TRUE;
		}

		if (FALSE === $result)
		{
			if ($this->debug == TRUE)
			{
				$this->_error('ftp_unable_to_connect');
			}
			$this->errmsg = '指定されたFTPサーバーに、接続できません。FTPサーバー名をご確認下さい。<br />もしくは、FTP接続の制限が考えられます。';
			return FALSE;
		}
		$this->isConnectable = TRUE;

		if ( ! $this->login())
		{
			if ($this->debug == TRUE)
			{
				$this->_error('ftp_unable_to_login');
			}
			$this->errmsg = 'ユーザー名、パスワードのいずれかが間違っています。';
			$this->close();
			return FALSE;
		}

		$this->isAuthentic = TRUE;

		// Set passive mode if needed
		if ($this->passive == TRUE)
		{
			if(! ftp_pasv($this->conn_id, TRUE) ){
				$this->passive = FALSE;
				$this->close();
				$this->connect();
			}
		}
		return TRUE;
	}

	/**
	 * FTP Login
	 */
	function login()
	{
		if ($this->ftps) {
			$result = array_pop(ftp_raw($this->conn_id, 'USER '. $this->username));
			if (preg_match('/^331/',$result)) {
				$result = array_pop(ftp_raw($this->conn_id, 'PASS '. $this->password));
				return preg_match('/^230/', $result);
			}
			else {
				$result = $this->conn_id = @ftp_ssl_connect($this->hostname, $this->port);
				if (FALSE === $result)
				{
					if ($this->debug == TRUE)
					{
						$this->_error('ftp_unable_to_connect');
					}
					$this->errmsg = '指定されたFTPサーバーに、接続できません。FTPサーバー名をご確認下さい。<br />もしくは、FTP接続の制限が考えられます。';
					$this->errmsg .= '<br />また、FTPS のアクセスができない可能性もありますので、チェックを外してみてください。';
					return FALSE;
				}
				$this->isConnectable = true;
				return @ftp_login($this->conn_id, $this->username, $this->password);
			}			
		}
		else
		{
		echo '<!-- ftp:';
		var_dump($this->conn_id, $this->username, $this->password);
		echo ' -->';
			return @ftp_login($this->conn_id, $this->username, $this->password);
		}
	}
	
	/**
	 *   list_files の結果から"." と".." を削除した配列を返す
	 *
	 *   NOTICE:
	 *     Ftp::list_files() のwrapper
	 */
	function ls($path = '.', $option= '-a ') {
		$list = $this->list_files($path, $option);
		
		$retarr = array();
		foreach ($list as $i => $path) {
			$fname = basename($path);
			if ($fname != '.' && $fname != '..') {
				$retarr[$i] = $path;
			}
		}
		
		return $retarr;
	}
	
	/**
	 *   指定したファイルの内容を文字列として返す
	 *
	 *   @param string $fpath path from login root OR abs path
	 */
	function read($fpath) {
		//絶対|相対パスチェック
		if ($fpath{0} != '/') {
			$fpath = $this->loginroot. '/'. $fpath;
		}
		if ($this->is_exists($fpath) && !$this->is_dir($fpath)) {
			$tmpfile = tempnam("tmp", "hkntmp-");
			$this->download($tmpfile, $fpath, FTP_BINARY);
			$data = file_get_contents($tmpfile);
			unlink($tmpfile);
			return $data;
		}
		//読み込めない
		else {
			$this->errmsg = 'ファイルが存在しないか、あるいは存在しないフォルダです。';
			return FALSE;
		}
	}

	/**
	 *   指定したファイルに文字列を書き込む
	 *
	 *   @param string $fpath path from Login root OR abs path
	 *   @param string $str   write data
	 */
	function write($fpath, $str, $permission = null) {
		//絶対|相対パスチェック
		if ($fpath{0} != '/') {
			$fpath = $this->loginroot. '/'. $fpath;
		}

		$tmpfile = tempnam('tmp', 'hkntmp-');
		file_put_contents($tmpfile, $str);
		$this->upload($tmpfile, $fpath, FTP_BINARY, $permission);
		unlink($tmpfile);
		return TRUE;	
	}
	
	/**
	 *   利用規約を書いた文書ファイルを送信する
	 */
	function writeDescription($desc)
	{
		$rempath = $this->dir. '/'. DESCRIPTION_FILE;
		$this->write($rempath, $desc, 0644);
		
		return TRUE;
	}
	
	/**
	 *   FTP ログインルートフォルダに移動する
	 */
	function changerdir() {
		return $this->changerdir($this->loginroot);
	}
	/**
	 *   インストールフォルダに移動する
	 *
	 *   Override の必要がある場合もあります
	 */
	function changeidir() {
		return $this->dir === '' || $this->changedir($this->dir);
	}
	
	/**
	 *   インストールシステムを利用できるかチェックする
	 *   チェック項目は
	 *   ・指定されたディレクトリが存在する
	 *   ・指定されたディレクトリに書き込み権限がある
	 *   ・URLが正しいか
	 *   ・サーバー変数は正常に取得できるか
	 *  
	 */
	function serverTest()
	{
		//ログインルートを保存
		$this->loginroot = $this->pwd();

		//インストールディレクトリに移動
		$this->debug_msg[] = 'is_exists('.$this->dir.') = '.$this->is_exists($this->dir);
		$this->debug_msg[] = 'changeidir() = '.$this->changeidir();

		if ($this->is_exists($this->dir) && $this->changeidir())
		{
			$this->existInstallDir = TRUE;

			//書き込み権限の確認
			$this->_checkWritable();
		}
		else
		{
			$this->existInstallDir = FALSE;
			$this->errmsg = '指定されたフォルダは、存在しません。確認してください。';
		}
		
		//ログインルートに戻る
		$this->changedir($this->loginroot);
		$this->server = $this->hostname.','.$this->username.','.$this->dir;

		return ($this->errmsg == '') ? TRUE : FALSE;
	}

	/**
	 *   チェックファイルを設置する
	 */
	function putChecker() {
		if (!$this->_is_conn()) {
			return FALSE;
		}
		if (!isset($this->r_fname)) {
			$this->r_fname = time() . '_chk.php';
		}

		$tmpfile = tempnam('tmp', 'hkntmp-');
		$stream ='<'. '?php
$msg     = "FAILED";
$script  = ($_SERVER["SERVER_PORT"] == 443 ? "https://" : "http://"); // scheme
$script .= $_SERVER["SERVER_NAME"];	// host
$script .= (($_SERVER["SERVER_PORT"] == 80 || $_SERVER["SERVER_PORT"] == 443) ? "" : ":" . $_SERVER["SERVER_PORT"]);  // port
$path    = $_SERVER["SCRIPT_NAME"];
if ($path{0} != "/") {
	if (! isset($_SERVER["REQUEST_URI"]) || $_SERVER["REQUEST_URI"]{0} != "/") die($msg);
	$parse_url = parse_url($script . $_SERVER["REQUEST_URI"]);

	if (! isset($parse_url["path"]) || $parse_url["path"]{0} != "/") die($msg);
	$path = $parse_url["path"];
}
$script .= $path;

if ( !preg_match(\'/^(https?|ftp)(:\/\/[-_.!~*\'()a-zA-Z0-9;\/?:\@&=+\$,%#]+)$/\',$script) && php_sapi_name() == "cgi") die($msg);
echo "<scripturl>".$script."</scripturl>";
';
		file_put_contents($tmpfile, $stream);

		return parent::upload($tmpfile, $this->r_fname, FTP_BINARY, 0666);
	}

	/**
	 *   チェックファイルを削除する
	 */
	function removeChecker() {
		if (!$this->_is_conn() || !isset($this->r_fname)) {
			return FALSE;
		}
		$result = $this->delete_file($this->r_fname);
		unset($this->r_fname);
		return $result;
	}
	
	/**
	 *   カレントフォルダに書き込み権限があるかチェック
	 */
	function _checkWritable() {
		if (!$this->_is_conn()) {
			return FALSE;
		}
		if (!is_null($this->isWritable)) {
			return $this->isWritable;
		}
		
		$r_fname = $this->r_fname = time().'_chk.php';
		$res = $this->putChecker();
		$this->removeChecker();
		if(!$res){
			$this->errmsg = '指定されたフォルダは、書き込み権限がありません。';
			return FALSE;
		}
		$this->isWritable = true;
		
		return TRUE;
	}
	
	/**
	 *   オプション配列を基にchmod をかける
	 *
	 *   USAGE:
	 *     オプション配列は[ファイル名]=>[権限] の連想配列。
	 *     * ですべてのファイル、*／ ですべてのディレクトリ、*.php ですべてのphp ファイル、といった指定が可能
	 *     ※ ファイル名はインストールフォルダからの相対パスで
	 */
	function chmodr($option = array())
	{
		if (count($option) == 0) {
			$option = $this->files;
		}
		$mods= array();
		
		foreach ($option as $file => $p) {
			if (!isset($mods[$p])) {
				$mods[$p] = array();
			}
			
			//絶対パスに変換して、chmod に渡す配列を作成
			if ($file{0} != '/') {
				$file = $this->dir . '/'. $file;
			}
			$filelist = $this->_createFileList($file);
			$mods[$p] = array_merge($mods[$p], $filelist);
		}

		//対象ファイルすべてchmodをする
		foreach ($mods as $p => $filelist)
		{
			foreach ($filelist as $filepath)
			{
				$this->chmod($filepath, $p);
			}
		}
		
		//インストールディレクトリが777 かどうか判定し、777 の場合、755 に、707 の場合、705 に変更する
		$pardir = dirname($this->dir);
		//ルートディレクトリの場合、諦める
		if ($pardir != $this->dir) {
			$list = ftp_rawlist($this->conn_id, $pardir);
			$dirname = basename($this->dir);
			foreach ($list as $finfo) {
				$finfo = preg_split('/\s+/', $finfo);
				$ficnt = count($finfo);
				if ($finfo[$ficnt-1] == $dirname) {
					$perm = $finfo[0];
					if ($perm[0] == 'd') {
						$ptns = array('d', 'r', 'w', 'x', '-');
						$rpls = array('',  '1', '1', '1', '0');
						$pnum = intval(str_replace($ptns, $rpls, $perm), 2);
	
						if ($pnum == 0777) {
							$this->chmod($this->dir, 0755);
						} else if ($pnum == 0707) {
							$this->chmod($this->dir, 0705);
						}
					}
				}
			}
		}
	}
	
	/**
	 *   chmodr の書式に従ってファイル一覧を作成して返す
	 */
	function _createFileList($file) {
		$filelist = array();
		// *／ が入っている場合: ディレクトリすべて
		if (($pos = strpos($file, '*/')) !== FALSE) {
			$prefix = substr($file, 0, $pos);
			$suffix = substr($file, $pos + 1);
			
			//ファイルリストを取得し、ディレクトリ名を入れる
			$ls = $this->ls($prefix, '');
			foreach ($ls as $i => $filename) {
				//ディレクトリであれば格納
				if ($this->is_dir($filename)) {
					$file = $prefix . basename($filename) . $suffix;
					$filelist = array_merge($filelist, $this->_createFileList($file));
				}
			}
		}
		// *.ext が入っている場合: 該当ファイルすべて
		else if (preg_match('/^(.*)\*(\.[a-z0-9]+)$/i', $file, $ms)) {
			$path = $ms[1];
			$ext = $ms[2];
			
			//ファイルリストを取得し、拡張子をチェック
			$ls = $this->ls($path, '');
			$extptn = "/\\". $ext. '$/';
			foreach ($ls as $i => $filename) {
				//該当ファイルであれば格納
				if (preg_match($extptn, $filename)) {
					$filelist[] = $filename;
				}
			}
		}
		// * が入っている場合: ファイル全て
		else if (substr($file, -1, 1) === '*') {
			$path = dirname($file);
			//ファイルリストを取得し、すべて追加する
			$filelist = array_merge($filelist, $this->ls($path, ''));
		}
		//ただのファイル名: そのまま配列に格納
		else {
			$filelist[] = $file;
		}
	
		return $filelist;
	}
	
	
	/**
	 *   インストールフォルダが存在するかどうか
	 */
	function existInstallDir() {
		return is_null($this->existInstallDir)? FALSE: $this->existInstallDir;
	}
	
	/**
	 *   ログを書き込む
	 *
	 *   FORMAT:
	 *     Y-m-d H:i:s,$uid,$uname,$email,$hostname,$url,$dir,$ip,$action
	 *
	 *   @param string $action 何をしたか
	 */
	function writeLog($action) {
		if ($this->skipLog) {
			return FALSE;
		}
		
		$log = array();

		$log[] = date("Y-m-d H:i:s");
		$log[] = $_SESSION['User']['id'];
		$log[] = str_replace(',', '、', $_SESSION['User']['lastname'].$_SESSION['User']['firstname']);
		$log[] = $_SESSION['User']['mailaddress'];
		$log[] = $this->hostname;
		$log[] = $this->url . '';
		$log[] = $this->dir . '';
		$log[] = getenv("REMOTE_ADDR");
		$log[] = $action;
		
		$log = join(',', $log). "\n";
	
		//make filename
		$logfile = 'log/'. date("Y-m"). '.txt';

		$lines = hkn_file($logfile);
		$lines[] = $log;
		
		if (hkn_fwrite($logfile, $lines)) {
		//	return TRUE;
		} else {
			$this->errmsg = 'error: can\'t write log';
		//	return FALSE;
		}

		//北研クラブにもログを残す
		$uid = $_SESSION['User']['id'];
		//製品版
		if (isset($_SESSION['User'][PRODUCT_CODENAME])) {
			$pid = $_SESSION['User']['items'][PRODUCT_CODENAME]['id'];
		}
		//体験版
		else {
			$pid = TRY_PRODUCT_ID;
		}
		$server = $this->hostname.','.$this->username.','.$this->dir;
		hkn_install_log($uid, $pid, $server, strtolower($action));
	}

	// ------------------------------------------------------------------------	
		
	/**
	 *   list_files の結果から"." と".." を削除した配列を返す
	 *
	 *   NOTICE:
	 *     Ftp::list_files() のwrapper
	 */
	function pwd_ls() {
		$path = '.';
		$option= '-a ';
		
		$list = $this->list_files($path, $option);

		$retarr = array();
		foreach ($list as $fpath) {
			$fname = basename($fpath);
			if ($fname != '.' && $fname != '..') {
				$retarr[] = ($path=='.') ? $fname : $fpath;
			}
		}
		
		return $retarr;
	}

	// ------------------------------------------------------------------------	
	
	/**
	* 与えられたWeb上でのパスの、FTP接続上のパスを返す
	*
	* @param string:絶対パス
	*/
	function get_ftp_ab_path($file)
	{
		//カレントディレクトリ下にあるディレクトリを取得
		$list = array();
		$ftp_pwd = $this->pwd();
		foreach($this->pwd_ls() as $f)
		{
			if($this->is_dir($ftp_pwd.'/'.$f))
			{
				$list[] = $f;
			}
		}

		//$fileのパスを分割して $dirsに格納
		$fname = basename($file);
		$dirs = explode('/', substr( dirname($file), 1));
		$str_file = file_get_contents($file);
		
		$cnt = count($dirs);
		$stack_dir = '';
		
		//$dirsをさかのぼりながら、
		$retval = FALSE;
		for($i=$cnt-1; $i>=0; $i--)
		{
			if( array_search($dirs[$i], $list) !== FALSE )
			{
				$stack_dir = $dirs[$i] .'/'. $stack_dir;
				$ftp_ab_path = $ftp_pwd.'/'.rtrim($stack_dir, '/').'/'.$fname;
				$str_ftp = $this->file_get_contents($ftp_ab_path);
				if ($str_file == $str_ftp)
				{
					$this->dir = $retval = $ftp_pwd.'/'.rtrim($stack_dir, '/').'/';
					break;
				}
			}
			else
			{
				$stack_dir = $dirs[$i] .'/'. $stack_dir;
			}
		}
		
		return $retval;
	}

	// ----------------------------------------------------------------------------
	
	/**
	* 与えら得たディレクトリが、Web上のディレクトリと合致するかチェックする。
	* 
	* @param string __FILE__
	* @param string FTP Directory
	* @return boolean
	*/
	function is_web_dir($file, $ftp_dir)
	{
		$str_file = file_get_contents($file);

		$bname = basename($file);		
		$str_ftp = $this->file_get_contents(rtrim($ftp_dir,'/').'/'.$bname);
		
		if( $str_file == $str_ftp)
		{
			$this->dir = rtrim($ftp_dir,'/').'/';
			return TRUE;
		}
		
		return FALSE;
	}

	// ----------------------------------------------------------------------------
	
	/**
	* サーバーのファイルをダウンロードする。
	* 
	* @param string filepath
	* @return string file stream
	*/
	function file_get_contents($file)
	{
		$tmpfile = tempnam("tmp", "hknftp-");
		$this->download($tmpfile, $file, FTP_BINARY);

		$str = file_get_contents($tmpfile);
		unlink($tmpfile);
		
		return $str;
	}

	// ----------------------------------------------------------------------------
	
	/**
	* ディレクトリを作成する（recursive）
	* 
	* @param array dirlist
	* @return boolean
	*/
	function mkdirr($dirs)
	{
		if (count($dirs) == 0)
		{
			return FALSE;
		}
		if ( ! $this->_is_conn())
		{
			return FALSE;
		}

		foreach ($dirs as $path)
		{
			$this->changeidir();
			$this->mkdir($path);
		}
		return TRUE;
	}

	// ----------------------------------------------------------------------------
	
	/**
	* ファイルアップロード
	* 
	* @param string localpath
	* @param string Remotepath
	* @return boolean
	*/
	function upload($localpath, $rempath)
	{
		if ( ! $this->_is_conn())
		{
			return FALSE;
		}

		$this->changeidir();
		return parent::upload($localpath, $rempath);
	}

	// ----------------------------------------------------------------------------
	
	/**
	* FTP情報の暗号化
	* 
	* @param string key
	* @return string encrypt ftp string
	*/
	function encrypt_ftp($key)
	{
		$sr = serialize(array('hostname'=>$this->hostname, 'username'=>$this->username, 'password'=>$this->password, 'dir'=>$this->dir));
		$mc = new ORMcrypt($key);
		$arr = $mc->encrypt($sr);
		return implode(',', $arr);
	}

	// ----------------------------------------------------------------------------
	
	/**
	* FTP情報の複合化
	* 
	* @param string key
	* @return array ftpinfo
	*/
	function decrypt_ftp($key, $codearr)
	{
		if ( ! is_array($codearr) || count($codearr) != 2 )
		{
			return FALSE;
		}

		$mc = new ORMcrypt($key);
		$data = $mc->decrypt($codearr[0], $codearr[1]);
		return unserialize($data);
	}
}
/**
 *   Hokuken Local class
 *   -------------------------------------------
 *   HKNLocal.php
 *   
 *   Copyright (c) 2010 hokuken
 *   http://hokuken.com/
 *   
 *   created  : 2010-03-17
 *   modified : 2010-11-05 利用規約を設置するよう変更
 *   
 *   @package		HKNTool
 *
 *
 *   北研商品全般に使える予定
 *   
 *   Usage :
 *     必ず ../config.php を読み込むこと。
 *
 *   TODO: commu/sys/lib/ のHKNFtp と統合する
 */

class HKN_Local{
	
	var $server = 'localhost';
	var $errmsg = '';
	
	/**
	* ディレクトリ作成
	* 
	* @param array dirlist
	* @return string file stream
	*/
	function mkdirr($dirs)
	{
		if (count($dirs) == 0)
		{
			return FALSE;
		}

		foreach ($dirs as $path)
		{
			@mkdir($path);
		}
		return TRUE;
	}

	// ----------------------------------------------------------------------------

	/**
	* ファイル削除
	* 
	* @param string filepath
	* @return
	*/
	function delete_file($path)
	{
		if ($path == "")
		{
			return FALSE;
		}

		if (file_exists($path))
		{
			unlink($path);
		}
	}


	// ----------------------------------------------------------------------------

	/**
	* ディレクトリ削除
	* 
	* @param string dirname or filename
	* @return
	*/
	function delete_dir($dir)
	{
		if (is_dir($dir))
		{
			$objects = scandir($dir);
			foreach ($objects as $object)
			{
				if ($object != "." && $object != "..")
				{
					if (filetype($dir."/".$object) == "dir")
					{
						$this->delete_dir($dir."/".$object);
					}
					else
					{
						unlink($dir."/".$object);
					}
				}
			}
			reset($objects);
			rmdir($dir);
		}
	} 

	// ----------------------------------------------------------------------------
	
	/**
	* ファイルアップロード
	* 
	* @param string localpath
	* @param string Remotepath
	* @return boolean
	*/
	function upload($localpath, $rempath)
	{
		if (file_exists($localpath))
		{
			if (copy($localpath, $rempath))
			{
				unlink($localpath);
				return TRUE;
			}
		}
		return FALSE;
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	* ファイル権限変更
	* 
	* @param array filelist
	* @return boolean
	*/
	function chmodr($option = array())
	{
		if (count($option) == 0) {
			return FALSE;
		}

		$mods= array();
		foreach ($option as $file => $p) {
			if (!isset($mods[$p])) {
				$mods[$p] = array();
			}

			$filelist = $this->_createFileList($file);
			$mods[$p] = array_merge($mods[$p], $filelist);
		}
		//対象ファイルすべてchmodをする
		foreach ($mods as $p => $filelist) {
			foreach ($filelist as $filepath) {
				@chmod($filepath, $p);
			}
		}

		$pwd = getcwd();
		$pnum = fileperms($pwd);
		if ($pnum == 0777)
		{
			@chmod($pwd, 0755);
		}
		else if ($pnum == 0707)
		{
			@chmod($pwddir, 0705);
		}

		return TRUE;
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	* chmodr の書式に従ってファイル一覧を作成して返す
	* 
	* @param array filelist
	* @return array filelist
	*/
	function _createFileList($file) {
		$filelist = array();
		// *／ が入っている場合: ディレクトリすべて
		if (($pos = strpos($file, '*/')) !== FALSE) {
			$prefix = substr($file, 0, $pos);
			$suffix = substr($file, $pos + 1);
			
			//ファイルリストを取得し、ディレクトリ名を入れる
			if (($ls = $this->ls($path)) !== FALSE)
			{
				foreach ($ls as $i => $filename) {
					//ディレクトリであれば格納
					if (is_dir($filename)) {
						$file = $prefix . basename($filename) . $suffix;
						$filelist = array_merge($filelist, $this->_createFileList($file));
					}
				}
			}
		}
		// *.ext が入っている場合: 該当ファイルすべて
		else if (preg_match('/^(.*)\*(\.[a-z0-9]+)$/i', $file, $ms)) {
			$path = $ms[1];
			$ext = $ms[2];
			
			//ファイルリストを取得し、拡張子をチェック
			if (($ls = $this->ls($path)) !== FALSE)
			{
				$extptn = "/\\". $ext. '$/';
				foreach ($ls as $i => $filename) {
					//該当ファイルであれば格納
					if (preg_match($extptn, $filename)) {
						$filelist[] = $filename;
					}
				}
			}
		}
		// * が入っている場合: ファイル全て
		else if (substr($file, -1, 1) === '*') {
			$path = dirname($file);
			//ファイルリストを取得し、すべて追加する
			if (($ls = $this->ls($path)) !== FALSE)
			{
				$filelist = array_merge($filelist, $ls);
			}
		}
		//ただのファイル名: そのまま配列に格納
		else {
			$filelist[] = $file;
		}
	
		return $filelist;
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	* ファイルリストから"." と".." を削除した配列を返す
	* 
	* @param string path
	* @return array filelist
	*/
	function ls($path = '.')
	{
		if (strlen($path) == 0){
			return FALSE;
		}
		$path = rtrim($path, "/") . "/";
		if( ! is_dir($path))
		{
			return FALSE;
		}
		
		$retarr = array();
		if( $dh = opendir($path))
		{
			while (false !== ($file = readdir($dh)))
			{
			    // Skip '.' and '..'
			    if ($file == '.' || $file == '..')
			    {
			        continue;
			    }
			    $path = rtrim($path, '/') . '/' . $file;
			    if (is_dir($path))
			    {
			        $retarr[] = $this->ls($path);
			    }
			    else
			    {
			        $retarr[] = $path;
			    }
			}
			closedir($dh);
		}
		return $retarr;
	}

	// ----------------------------------------------------------------------------
	
	/**
	 *   指定したファイルに文字列を書き込む
	 *
	 *   @param string $fpath path from Login root OR abs path
	 *   @param string $str   write data
	 */
	function write($fpath, $str, $permission = null)
	{
		if ($fpath == '')
		{
			return FALSE;
		}

		if (file_put_contents($fpath, $str) === FALSE)
		{
			return FALSE;
		}
		chmod($fpath, $permission);
		return TRUE;
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	 *   指定したファイルに文字列を書き込む
	 *
	 *   @param string $fpath path from Login root OR abs path
	 *   @param string $str   write data
	 */
	function writeDescription($desc)
	{
		return $this->write(DESCRIPTION_FILE, $desc, 0644);
	}
	
	function pwd()
	{
		return getcwd();
	}
	
	function changeidir()
	{
		@chdir(dirname(__FILE__));
	}
	
}
/**
* PHPのバージョンなどをチェックするためのクラス
*
* 
* @package		HKNTool
*/
class PHPChecker {

	private $values;
	
	/** 必要PHP バージョン*/
	var $requirePHPVer = "5.0";//適宜オーバーライドしてください

	/** PHP が利用可能かどうか*/
	var $enablePHP;
	
	/** エラーメッセージ */
	var $errmsg = '';
	
	function __construct()
	{
		$this->values = array();
	
		//php core
		$this->values['php_version'] = phpversion();
		$this->values['php_sapi_name'] =  php_sapi_name();
		
		if (substr($this->values['php_sapi_name'], 0, 3) == 'cgi')
		{
			$this->values['cgi-php'] = 1;
		}
		else
		{
			$this->values['cgi-php'] = 0;
		}
		
		$this->values['extensions'] = implode(', ', get_loaded_extensions());
		
		$this->_set_ini('safe_mode');
		$this->_set_ini('open_basedir');
	
		//server
		$ns = array(
			'HTTP_HOST', 'SERVER_NAME', 'SCRIPT_FILENAME', 'SCRIPT_NAME', 'REQUEST_URI','PHP_SELF'
		);
		foreach($ns as $n)
		{
			$this->_set_server_ini($n);
		}
		
		$this->values['__FILE__'] = __FILE__;

		//session
		$ns = array(
			'session.name',
			'session.save_path',
			'session.cookie_domain',
			'session.cookie_path',
			'session.save_path',
		);
		foreach($ns as $n)
		{
			$this->_set_ini($n);
		}

		//mbstring
		foreach(array('mbstring.encoding_translation', 'mbstring.internal_encoding') as $n)
		{
			$this->_set_ini($n);
		}
		
		//misc
		$ns = array(
			'allow_url_fopen', 'magic_quotes_gpc', 'upload_max_filesize','memory_limit',
		);
		foreach($ns as $n)
		{
			$this->_set_ini($n);
		}
	}
	
	function _set_ini($name)
	{
		$this->values[$name] = ini_get($name);
	}
	
	function _set_server_ini($name)
	{
		$this->values['$_SERVER[\''.$name.'\']'] = $_SERVER[$name];
	}
	
	/**
	* 書き込み可能かチェックする
	*/
	function is_editable(){
		
		$dirname = '';
		for($i=0; $i<20; $i++) //20回試行する
		{
			for($j=0; $j<10; $j++) //長さ10のランダムな数字のフォルダを作成
			{
				$dirname .= rand(0, 9);
			}
			
			if(! file_exists($dirname) )
			{
				break;
			}
			else
			{
				$dirname = '';
			}
		}
		
		if( $dirname == '')
		{
			die('error: rand error');
		}
		
		$is_w = FALSE;
		if( mkdir($dirname) ){
			$fname = $dirname.'/'.$dirname.'.txt';
			if( file_put_contents($fname, 'hoge') )
			{
				unlink($fname);
				$is_w = TRUE;
			}
			
			rmdir($dirname);
		}
		
		return $is_w;
	}
	
	/**
	* 情報を取得する
	*/
	function get_ini($key)
	{
		return isset($this->values[$key]) ? $this->values[$key] : '';
	}

	function check_php_version()
	{
		if (version_compare($this->values['php_version'], $this->requirePHPVer, '<')) {
			$this->errmsg = 'ご指定のサーバーは、PHP'.$this->values['php_version'] .' 環境ですので、動作しません。<br />PHP'.$this->requirePHPVer.'以上で動作します。';
			return $this->enablePHP = FALSE;
		}
		return TRUE;
	}
	
	function check_encoding($encording)
	{
		if ($this->values['mbstring.encoding_translation'])
		{
			if (mb_internal_encoding() != $encording) {
				$this->errmsg = '文字コードの設定が正しくありません。';
				return FALSE;
			}
		}
		return TRUE;
	}
	
	function check_ini($key)
	{
		if ( ! isset($this->values[$key]))
		{
			return FALSE;
		}

		return ($this->values[$key]) ? TRUE : FALSE;
	}
} 
class EnsmallAuth {

	/* addons */
	var $addons = array();
	
	/* 送信データの格納 */
	var $query_data = array();

	/* レスポンスデータ */
	var $res;
	
	/* passcode */
	private $passcode = FALSE;
	
	/* バージョン情報 */
	var $version;
	var $revision;
	
	/* インストールURL */
	var $install_url;

	/* インストール回数 */
	var $install_count;

	/* インストール最大回数 */
	var $install_limit;

	/* Ensmall Club 情報 */
	var $user_id;
	var $product_id;

	/* Product Check */
	var $isNew = FALSE;
	var $doRestore = FALSE;
	// ! need change by product ----- 
	var $isQHMTry  = FALSE;
	var $isOpenQHM = FALSE;
	var $isQHMLite = FALSE;
	var $isACCafe  = FALSE;
	var $hasQDesigner = FALSE;
	// ------------------------------

	/* tryinfo */
	var $tryinfo = array();
	var $isMoveTry = FALSE;
	
	/* エラーメッセージ */
	var $errmsg ='';

	/* エラーメッセージ */
	var $errstatus;

	/** getProps() で取得できない非公開プロパティ */
	var $priProps = array(
		'res', 'errmsg'
	);

	/* プロキシー接続をするか */
	var $use_proxy = FALSE;
	
	/* プロキシーホスト */
	var $proxy_host;

	/* サイト情報 */
	var $username;
	var $password;
	
	/* メール設定 */
	var $language = 'Japanese';
	var $encoding = 'UTF-8';
	var $from = array('name'=>"北摂情報学研究所", 'email'=>"customer@hokuken.com");
	var $return_path = '';
	var $reply_to = '';
	var $x_mailer = '';
	var $to = array('name'=>'', 'email'=>'');

	/**
	* コンストラクタ
	*
	* @param string email
	* @param string password
	* @param string product_id
	* @return 
	*/
	function EnsmallAuth($url='')
	{	
		$this->add_query_data('codename', PRODUCT_CODENAME);
		if ($url != '')
		{
			$this->install_url = $url;
		}
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	* Ensmall Clubへ認証
	* 
	* @param string ensmall club url
	* @return integer error code
	*/
	function auth($email, $password)
	{
		$this->add_query_data('email', $email);
		$this->add_query_data('password', sha1(md5($password)));
		$this->to['email'] = $email;

		$req_data = array(
			'method'=>'POST',
			'post'=>$this->query_data,
		);
		if ($this->use_proxy)
		{
			$req_data['proxy_host'] = $this->proxy_host;
		}

		$url = ENSMALL_CLUB_URL . 'users/chk_ensmall_auth/';
		$res = http_req($url, $req_data);
		if ($data = $this->_search_header($res['header'],'X-ENSMALL-RETURN'))
		{
			$ret = unserialize(base64_decode($data));
			if ($ret['passcode'] !== FALSE) {
				$this->_set_passcode($ret['passcode']);
				$this->install_count     = $ret['install_count'];
				$this->install_limit     = $ret['install_limit'];
				$this->user_id           = $ret['user_id'];
				$this->product_id        = $ret['product_id'];
				$this->tryinfo           = $ret['tryinfo'];
				if ($ret['addons'] != '')
				{
					$this->addons = $ret['addons'];
				}
			}

			$this->errmsg = $ret['message'];
			return $this->errstatus = $ret['status'];
		}
		return FALSE;
	}

	// ----------------------------------------------------------------------------
	
	/**
	* 送信データの追加
	* 
	* @param string key
	* @param string value
	* @return
	*/
	function add_query_data($key, $val)
	{
		$this->query_data[$key] = $val;
	}

	// ----------------------------------------------------------------------------
	
	/**
	* データの取得
	* 
	* @param string url
	* @param array query
	* @return mixed response
	*/
	function get_data($url, $query)
	{
		if (count($this->passcode) != 2)
		{
			return FALSE;
		}
		
		$query['code1'] = $this->passcode[0];
		$query['code2'] = $this->passcode[1];
		
		$req_data = array('method'=>'POST','post'=>$query);
		if ($this->use_proxy)
		{
			$req_data['proxy_host'] = $this->proxy_host;
		}

		$res = http_req($url, $req_data);
		return trim($res['data']);
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	* インストーラーのバージョンチェック
	* 
	* @return boolean TRUE or FALSE(need change)
	*/
	function check_installer()
	{
		$url = ENSMALL_PRODUCT_URL.PRODUCT_CODENAME.'/get_installer_version.php';
		$param = array(
		);

		// get upload list
		$res = $this->get_data($url, $param);
		if ($res === FALSE)
		{
			return TRUE;
		}
		
		$data = unserialize($res);
		if ($data !== FALSE)
		{
			if (INSTALLER_VERSION < $data['ver'])
			{
				return FALSE;
			}
		}
		
		return TRUE;
	}

	// ----------------------------------------------------------------------------
	
	/**
	* 更新するファイルリストを取得
	* 
	* @param string mode
	* @param string addon codename
	* @return string tempfilename or FALSE
	*/
	function get_updateFileList($mode, $addonname="")
	{
		$mode = ($addonname == "") ? $mode : 'addon';
		$list_url = ENSMALL_PRODUCT_URL.PRODUCT_CODENAME.'/get_file_list.php';
		$param = array(
			'mode' => $mode,
			'rev'  => $this->revision,
			'addonname'=>$addonname,
		);

		// get upload list
		$res = $this->get_data($list_url, $param);
		if ($res === FALSE)
		{
			return FALSE;
		}
		
		$uplist = unserialize($res);
		return $uplist;
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	* 指定したファイルをダウンロード
	* 
	* @param string url
	* @param string file
	* @return string tempfilename or FALSE
	*/
	function download($file)
	{
		$url = ENSMALL_PRODUCT_URL.PRODUCT_CODENAME.'/dl.php';
		$query = array('file' => $file);
		$query['limit'] = $this->getTryLimit();
		
		$res = $this->get_data($url, $query);
		if ($res === ENSMALL_STATUS_ERROR_INSTALL_OVER)
		{
			$this->errmsg = 'インストール回数が超過しています。';
			return $res;
		}
		else if ($res === ENSMALL_STATUS_ERROR)
		{
			$this->errmsg = 'ファイルをダウンロードできませんでした [file:'.$file.']';
			return FALSE;
		}
		else if (strlen($res) > 0)
		{
			$tmpfile = tempnam("tmp", "hknEns-");
			if  (file_put_contents($tmpfile, $res) !== FALSE)
			{
				return $tmpfile;
			}
		}

		return FALSE;
	}

	// ----------------------------------------------------------------------------
	
	/**
	* パスコードのセット
	* 
	* @param mixed passcode
	* @return
	*/
	function _set_passcode($val)
	{
		$this->passcode = $val;
	}

	// ----------------------------------------------------------------------------
	
	/**
	* プロキシーホストのセット
	* 
	* @param string proxy
	* @return
	*/
	function set_proxy($val)
	{
		if ($val != '') {
			$this->use_proxy = TRUE;
			$this->proxy_host = $val;
		}
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	* Ensmall Club に認証できているか
	* 
	* @param mixed passcode
	* @return
	*/
	function is_connect()
	{
		if ( ! isset($_SESSION['ensmall_info']))
		{
			return FALSE;
		}
		if ($this->passcode !== FALSE)
		{
			return TRUE;
		}
		
		return FALSE;
	}

	// ----------------------------------------------------------------------------
	
	/**
	* ヘッダー情報の取得
	* 
	* @param string header
	* @param string 検索文字列
	* @return ヘッダー情報
	*/
	function _search_header($header, $needle='')
	{
		if ( ! (strlen($header) > 0 && strlen($needle) > 0))
		{
			return FALSE;
		} 
		$hlist = explode("\r\n", $header);
		foreach ($hlist as $h)
		{
			$t = explode(':', $h);
			if (strtolower(trim($t[0])) == strtolower($needle))
			{
				if (($pos = strpos($h, '|')) !== FALSE)
				{
					return substr($h, ($pos+1));
				}
			}
		}
		return FALSE;
	}

	// ----------------------------------------------------------------------------
	
	/**
	* プロパティを取得する
	* 
	* @param
	* @return array this class properties
	*/
	function getProps()
	{
		$priprs = $this->priProps;

		$vars = get_object_vars($this);
		$retvars = array();
		foreach ($vars as $key => $var) {
			if (!in_array($key, $priprs)) {
				$retvars[$key] = $var;
			}
		}
		return $retvars;
	}

	// ----------------------------------------------------------------------------
	
	/**
	* セッションにデータを保存する
	* 
	* @param 
	* @return
	*/
	function saveProps()
	{
		$_SESSION['ensmall_info'] = $this->getProps();
	}	

	// ----------------------------------------------------------------------------
	
	/**
	* プロパティをセッションから読込む
	* 
	* @param 
	* @return
	*/
	function readProps()
	{
		if ( ! isset($_SESSION) || ! isset($_SESSION['ensmall_info']) )
		{
			return FALSE;
		}
		
		$this->setProps($_SESSION['ensmall_info']);
	
	}

	// ----------------------------------------------------------------------------
	
	/**
	* プロパティをセットする
	* 
	* @param array property
	* @return
	*/
	function setProps($props)
	{
		foreach ($props as $key => $prop)
		{
			if ( ! in_array($key, $this->priProps) && property_exists(__CLASS__, $key))
			{
				$this->$key = $prop;
			}
		}
	}

	// ----------------------------------------------------------------------------
	
	/**
	* プロパティをセットする
	* 
	* @param array property
	* @return
	*/
	function get_description($option = '', $urlret = false)
	{
		$uri = ENSMALL_CLUB_URL . 'products/get_description/'. PRODUCT_CODENAME. ($option? '/'. $option: '');
		if ($urlret) {
			return $uri;
		}
		
		$res = $this->get_data($uri, array());
		return $res;
	}

	// ----------------------------------------------------------------------------
	
	/**
	* メールアドレスを取得する
	* 
	* @param
	* @return string email
	*/
	function get_email()
	{
		return isset($this->query_data['email']) ? $this->query_data['email'] : '';
	}


	// ----------------------------------------------------------------------------
	
	/**
	* メール本文の置換
	* 
	* @param array search data & value
	* @param string mail body
	* @return string mail body
	*/
	function replace_mail_body($sr, $body)
	{
		if ( ! is_array($sr) || count($sr) == 0)
		{
			return $body;
		}
		foreach ($sr as $key => $val)
		{
			$body = str_replace('<%'.$key.'%>', $val, $body);
		}
		return $body;
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	* メール送信
	* 
	* @param
	* @return 
	*/
	function send($subject, $body)
	{
		mb_language($this->language);
		mb_internal_encoding($this->encoding);
		$mail_encode = 'ISO-2022-JP';
		
		$from_name = $this->from['name'];
		$from_adr = $this->from['email'];
		$rpath = ($this->return_path=='') ? $from_adr : $this->return_path;
		$repto = ($this->reply_to=='') ? $from_adr : $this->reply_to;
		$xmailer = ($this->x_mailer=='') ? "PHP/" . phpversion() : $this->x_mailer;
		$to = $this->to['email'];
		
		$headers =  "MIME-Version: 1.0\n".
					"From: ". $this->mime(mb_convert_encoding($from_name, $mail_encode, $this->encoding), $mail_encode). " <{$from_adr}>"."\n".
					"Reply-To: {$repto}"."\n".
					"Content-Type: text/plain;charset=ISO-2022-JP\n".
					"X-Mailer: {$xmailer}";

		$subject = mb_convert_encoding($subject, $mail_encode, $this->encoding);
		mb_internal_encoding($mail_encode);
		$subject = mb_encode_mimeheader( $subject, $mail_encode );
		mb_internal_encoding($this->encoding);

		$body = str_replace("\r", "", $body);
		$body = mb_convert_encoding($body, $mail_encode, $this->encoding);
		
		$sendmail_params  = "-f $from_adr";
		
		if( ini_get('safe_mode') ){
			return mail($to, $subject,	$body, $headers);
		}
		else{
			return mail($to, $subject,	$body, $headers, $sendmail_params);
		}
	}

	// ----------------------------------------------------------------------------

	/**
	*   内部エンコードを変えて、mb_encode_mimeheader() をかける
	*   長い差し出し人名などに対応（長すぎると消える）
	*
	* @param string 変換文字列 
	* @param string エンコード 
	* @return string 変換後の文字列
	*/
	function mime($str = '', $mail_encode)
	{
		mb_internal_encoding($mail_encode);
		$subject = mb_encode_mimeheader( $str, $mail_encode );
		mb_internal_encoding($this->encoding);
		return $subject;
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	* メールの作成
	* 
	* @param
	* @return 
	*/
	function send_mail()
	{
		// ! need change by prodcut
		$subject = '管理者情報を設定しました';
		$body = '
こんにちは。
北研サポートです。

あなたのホームページ編集用のパスワードを設定いたしました。
以下の通りです

・サイトのURL
<%url%>

・サイトのログインURL
<%loginurl%>

・ユーザー名
<%username%>


パスワードは、設定されたパスワードをご入力ください

';
		$body = $this->replace_mail_body(
			array(
				'url'      => $this->install_url,
				'loginurl' => rtrim($this->install_url, '/').'/'.'?cmd=qhmauth',
				'username' => $this->username,
			),
			$body
		);

		$this->send($subject, $body);
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	 *   ログの出力
	 *
	 *   @param string $status install or update or restore or uninstall
	 *   @param string $server サーバー情報
	 *   @param string $pid Product ID
	 *
	 *   @return boolean 成功
	 */
	function install_log($status, $server='localhost', $pid='')
	{
		$url = ENSMALL_CLUB_URL.'product_installs/install_log/__UID__/__PID__/__SERVER__/__STATUS__/d41da6ce50bdf4e458514e8d4a195e63/';
		$search = array('__UID__', '__PID__', '__SERVER__', '__STATUS__');
		
		$server = str_replace('/', '\\', $server); //cakephpによって、%2Fが、/ と認識されてうまく動作しないから
		$pid = ($pid == '') ? $this->product_id : $pid;

		$rep = array($this->user_id, $pid, rawurlencode($server), rawurlencode($status));
		$url = str_replace($search, $rep, $url);
		$req_data = array('method'=>'POST', 'post'=>array('url'=>$this->install_url));
		if ($this->use_proxy)
		{
			$req_data['proxy_host'] = $this->proxy_host;
		}
		$res = http_req($url, $req_data);
		return TRUE;
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	 *   新規インストールかどうか
	 *
 	 * @param 
	 * @return boolean TRUE：新規インストール
	 */
	function isNew() {
		return is_null($this->isNew)? FALSE: $this->isNew;	
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	 *   体験版かどうか
	 *
 	 * @param 
	 * @return boolean TRUE:体験版
	 */
	function isTry()
	{
		return (isset($this->tryinfo['isTry'])) ? $this->tryinfo['isTry'] : TRUE;
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	 *   体験版の有効期限の設定
	 *
 	 * @param integer timestamp
	 * @return
	 */
	function setTryLimit($t)
	{
		$this->tryinfo['sys_expire'] = $t;
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	 *   体験版の有効期限の取得
	 *
 	 * @param
	 * @return integer timestamp
	 */
	function getTryLimit()
	{
		if (isset($this->tryinfo['sys_expire']))
		{
			return $this->tryinfo['sys_expire'];
		}
		return '';
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	 *   体験スペースを利用するかどうか
	 *
 	 * @param 
	 * @return TRUE or FALSE
	 */
	function hasTrySpace()
	{
		return (isset($this->tryinfo['useSpace']) ? $this->tryinfo['useSpace'] : FALSE);
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	 *   体験スペースのファイルリストを取得
	 *
 	 * @param
	 * @return array file list
	 */
	function getTrySpaceFileList()
	{
		$id = $this->_get_tryspace_id();
		if ($id == ''){
			return array();
		}
		
		// get upload list
		$url = $this->_get_tryspace_url().'rem_get_filelist.php';
		$param = array(
			'dirname' => $id,
		);	
		$res = $this->get_data($url, $param);
		if ($res === FALSE)
		{
			return array();
		}
		
		return unserialize($res);		
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	* 指定したファイルをEnsmall Clubからダウンロード
	* 
	* @param string file
	* @return string tempfilename or FALSE
	*/
	function download_trySpaceFile($file)
	{
		$id = $this->_get_tryspace_id();
		if ($id == ''){
			return FALSE;
		}

		// get upload list
		$url = $this->_get_tryspace_url().'rem_download.php';
		$param = array(
			'file' => $file,
			'dirname' => $id,
		);	
		$res = $this->get_data($url, $param);
		if ($res === ENSMALL_STATUS_ERROR)
		{
			$this->errmsg = 'ダウンロードできませんでした。[filename:'.$file.']';
			return FALSE;
		}
		if (strlen($res) > 0)
		{
			$tmpfile = tempnam("tmp", "hknEns-");
			if  (file_put_contents($tmpfile, $res) !== FALSE)
			{
				return $tmpfile;
			}
		}
		return FALSE;
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	 *   体験スペースの有効期限を取得
	 *
 	 * @param
	 * @return integer
	 */
	function setTrySpaceLimit()
	{
		$id = $this->_get_tryspace_id();
		if ($id == ''){
			return FALSE;
		}

		// get upload list
		$url = $this->_get_tryspace_url().'rem_get_limit.php';
		$param = array(
			'file' => $file,
			'dirname' => $id,
		);	
		$res = $this->get_data($url, $param);
		if ($res != '')
		{
			$this->setTryLimit($res);
		}
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	 *   体験スペースにダウンロードファイルを設置
	 *
 	 * @param
	 * @return 
	 */
	function putTrySpaceEnd()
	{
		$id = $this->_get_tryspace_id();
		if ($id == ''){
			return FALSE;
		}

		// get upload list
		$url = $this->_get_tryspace_url().'rem_put_endfile.php';
		$param = array(
			'file' => $file,
			'dirname' => $id,
		);	
		$res = $this->get_data($url, $param);
	}
	
	// ----------------------------------------------------------------------------
	
	/**
	 *   体験スペースのURLを取得
	 *
 	 * @param
	 * @return string URL
	 */
	function _get_tryspace_url()
	{
		if ( ! isset($this->tryinfo['spaceurl']) || $this->tryinfo['spaceurl'] == '')
		{
			return '';
		}
		$spaceurl = $this->tryinfo['spaceurl'];
		return dirname($spaceurl).'/sys/';
	}

	// ----------------------------------------------------------------------------
	
	/**
	 *   体験スペースのIDを取得
	 *
 	 * @param
	 * @return string ID
	 */
	function _get_tryspace_id()
	{
		if ( ! isset($this->tryinfo['spaceurl']) || $this->tryinfo['spaceurl'] == '')
		{
			return '';
		}
		$spaceurl = $this->tryinfo['spaceurl'];
		return basename($spaceurl);
	}

	// ----------------------------------------------------------------------------
	
	/**
	 *   システムの修復を行うか？
	 *
 	 * @param
	 * @return boolean TRUE:行う
	 */
	function doRestore()
	{
		return is_null($this->doRestore)? FALSE: $this->doRestore;	
	}

	// ----------------------------------------------------------------------------
	
	/**
	 *   商品のチェック
	 *
 	 * @param
	 * @return boolean
	 */
	function check_product()
	{
		// ! need change by prodcut

		if (file_exists(PRODUCT_CHECK_FILE))
		{
			$this->isNew = FALSE;
		}
		else
		{
			$this->isNew = TRUE;
		}
		
		// インストール回数チェック
		if ($this->isNew)
		{
			// limit が 0の場合は、無制限
			if ($this->install_limit > 0 && $this->install_count > $this->install_limit)
			{
				$this->errmsg = 'インストール回数が超過しています。';
				return FALSE;
			}
		}
		
		// 更新時
		if ( ! $this->isNew())
		{
			// QHMモバイルの場合は、インストール、アップデートをしない
			if (file_exists('./QHMMOBILE.txt'))
			{
				$this->errmsg = 'QHMモバイルがインストールされています。<br />QHMモバイルをアンインストールしてください。';
				return FALSE;
			}

			// qhm.ini.phpのチェック：なければ、インストールシステムへ
			if ( ! file_exists(PRODUCT_CONFIG_FILE))
			{
				$this->errmsg = 'バージョンが古いため、インストールシステムをご利用ください。<br /><a href="'.PRODUCT_INSTALL_SYSTEM.'" title="インストールシステム">&gt;&gt; インストールシステムへ</a>';
				return FALSE;
			}

			// バージョンチェック
			$this->_checkVersion();

			// 体験版の場合：更新日時をチェックする
			if ($this->isTry())
			{
				$fpath = './lib/qhm_init.php';
				if (file_exists($fpath))
				{
					$qhminit = file_get_contents($fpath);
					//timestamp を取り出す
					if (preg_match('/\$timestamp\s=\s(\d+)?;/', $qhminit, $ms))
					{
						$this->setTryLimit(trim($ms[1]));
					}
				}
			}
			else {
				$hasFwd3 = FALSE;
				$hasSwfu = FALSE;
				
				// swfuチェック				
				if (file_exists('./swfu/config.php'))
				{
					$hasSwfu = TRUE;
				}

				// fwd3チェック
				if (file_exists('./fwd3/sys/config.php'))
				{
					$hasFwd3 = TRUE;
				}

				// 体験版チェック
				if (file_exists('./lib/qhm_init.php')) {
					//qhm_init に体験版限定関数が定義されている
					$qinitstr = file_get_contents('./lib/qhm_init.php');
					if (preg_match('/function rmdir_all/', $qinitstr)) {
						$this->isQHMTry = TRUE;
						$this->doRestore = TRUE;
					}
				}

				// Open QHMチェック：default.ini.php に other_plugin を持たない
				$fpath = './default.ini.php';
				if (file_exists($fpath))
				{
					$defini = file_get_contents($fpath);
					//$other_plugins の中身があるかどうか調べる
					if (preg_match('/\$other_plugins\s=\sarray\(\);/', $defini)) {
						$this->isOpenQHM = TRUE;
						$this->doRestore = TRUE;
					}
				}
			
				if ($hasSwfu && ! $hasFwd3)
					// QHMLite チェック：other_plugins はもたない かつ swfu はあるけど、fwd3 がない
					if ($this->version >= 4.5 && $this->isOpenQHM) {
					{
						$this->isQHMLite = TRUE;
					}
					// ACCafe チェック
					if (file_exists('./ACCAFE.txt'))
					{
						$this->isACCafe = TRUE;
					}
					$this->doRestore = TRUE;
				}
				
			}
		}
		
		$this->_checkAddon();
		$this->saveProps();

		return TRUE;
	}

	// ----------------------------------------------------------------------------
	
	/**
	 *   商品のバージョンチェック
	 *   ! need change by product
	 *
 	 * @param
	 * @return
	 */
	function _checkVersion()
	{
		$ini = './lib/init.php';
		if (file_exists($ini)) {
			$inistr = file_get_contents($ini);
			if( preg_match("/QHM_VERSION', '(.*?)'/", $inistr, $ms))
			{
				$this->version = floatval($ms[1]);
				$this->revision = preg_match("/QHM_REVISION', '(.*)'/", $inistr, $ms2)? intval($ms2[1]): 0;
			} 
			else
			{
				$this->errmsg = 'バージョン情報が取得できません:1';
			}
		}
	}
	

	// ----------------------------------------------------------------------------
	
	/**
	 *   アドオンチェック
	 *   ! need change by product
	 *
 	 * @param
	 * @return
	 */
	function _checkAddon()
	{
		foreach ($this->addons as $key => $row)
		{
			if (is_dir($row['dir']))
			{
				$this->addons['installed'] = TRUE;
			}
			else
			{
				$this->addons['installed'] = FALSE;
			}
		}
	}
	
}


$ftp_info = array(
	'hostname' => 'localhost',
	'username' => '',
	'password' => '',
	'dir'      => '',
	'debug'    => DEBUG,
);

$error = '';
$warning = '';
$viewfunc = 'view_club_login';
$vdata = array('error'=>'');

$post = input_filter($_POST);
$get = input_filter($_GET);

$ens = new EnsmallAuth();

// ! Ensmall club login	
if (isset($_POST['club_login']))
{
	$email      = $post['email'];
	$password   = $post['password'];
	$url        = $post['install_url'];
	$use_proxy  = $post['use_proxy'];
	$proxy_host = $post['proxy_host'];

	// Ensmall Club Auth
	$ens->install_url = $url;
	if ($use_proxy)
	{
		$ens->set_proxy($proxy_host);
	}

	$res = $ens->auth($email, $password);
	if ($res === ENSMALL_STATUS_SUCCESS && $ens->check_product())
	{
		if ($ens->isNew())
		{
			if ( ! $_SESSION['is_editable'])
			{
				$vdata['ftp_type'] = 'default';
				$viewfunc = 'view_ftp_login';
			}
			else
			{
				// confirm
				$fm = get_uploader();
				check_installer($ens, $fm);
				$vdata['ens'] = $ens;
				$viewfunc = 'view_confirm';
			}
		}
		else
		{
			// Update or Uninstall or Reset Password
			$viewfunc = 'view_admin_login';
		}
	}
	else
	{
		$vdata['email'] = $email;
		$vdata['error'] = $ens->errmsg;
		$viewfunc = 'view_club_login';
	}
}
// ! ftp login	
else if (isset($_POST['ftp_login']))
{
	$ens->readProps();

	$ftp_info['username'] = $post['ftp_username'];
	$ftp_info['password'] = $post['ftp_password'];
	
	if (isset($post['ftp_hostname']))
	{
		$ftp_info['hostname'] = $post['ftp_hostname'];
	}
	if (isset($post['install_dir']))
	{
		$ftp_info['dir'] = $post['install_dir'];
	}

	$fm = new HKN_FTP();

	// FTP login
	if ($fm->connect($ftp_info))
	{
		if (($abpath = $fm->get_ftp_ab_path(__FILE__)) === FALSE)
		{
			// display web dir form
			$fm->is_web_dir(__FILE__, $ftp_info['dir']);
		}
		if ($fm->serverTest())
		{
			$fm->saveProps();
			check_installer($ens, $fm);
			$vdata['ens'] = $ens;
			$viewfunc = 'view_confirm';
		}
		else
		{
			// invalid dir
			$vdata['ftp_type'] = 'full';
			$vdata['error'] = $fm->errmsg;
			$viewfunc = 'view_ftp_login';
		}
	}
	else
	{
		// cannot connect
		$vdata['ftp_type'] = 'default';
		$vdata['error'] = $fm->errmsg;
		$viewfunc = 'view_ftp_login';
	}
}
// ! admin login
else if (isset($_POST['admin_login']))
{
	$ens->readProps();
	$fm = new HKN_FTP();

	$password = $post['admin_password'];
	
	$encrypt_ftp = get_ini_data('encrypt_ftp');
	$username = get_ini_data('username');
	
	$org_password = get_ini_data('passwd');
	$cmp_password = '{x-php-md5}'.md5($password);
	
	if ($org_password != $cmp_password)
	{
		$vdata['error'] = '管理者パスワードが正しくありません';
		$viewfunc = 'view_admin_login';
	}
	else
	{
		if ( ! $_SESSION['is_editable'])
		{
			$ftp_info = $fm->decrypt_ftp($username.$password, explode(',', $encrypt_ftp));
		
			// FTP login
			if ($fm->connect($ftp_info))
			{
				if ($fm->serverTest())
				{
					$fm->saveProps();
					check_installer($ens, $fm);
					$vdata['ens'] = $ens;
					$viewfunc = 'view_confirm';
				}
				else
				{
					// invalid dir
					$vdata['ftp_type'] = 'full';
					$vdata['error'] = $fm->errmsg;
					$viewfunc = 'view_ftp_login';
				}
			}
			else
			{
				// cannot connect
				$vdata['ftp_type'] = 'default';
				$vdata['error'] = $fm->errmsg;
				$viewfunc = 'view_ftp_login';
			}
		}
		else
		{
			// confirm
			$fm = get_uploader();
			check_installer($ens, $fm);
			$vdata['ens'] = $ens;
			$viewfunc = 'view_confirm';
		}
	}
}
// ! install
else if (isset($_POST['install']))
{
	$ens->readProps();
	$fm = get_uploader();
	if ($fm->errmsg == '')
	{
		$vdata['ens'] = $ens;
		$vdata['fm'] = $fm;
		$vdata['mode'] = 'install';
		$vdata['exec_func'] = 'upload_files';
		$viewfunc = 'view_do_now';
	}
}
// ! update
else if (isset($_POST['update']))
{
	$ens->readProps();
	$fm = get_uploader();
	if ($fm->errmsg == '')
	{
		$vdata['ens'] = $ens;
		$vdata['fm'] = $fm;
		$vdata['mode'] = 'update';
		$vdata['exec_func'] = 'upload_files';
		$viewfunc = 'view_do_now';
	}
}
// ! restore
else if (isset($_POST['restore']))
{
	$ens->readProps();
	$fm = get_uploader();
	if ($fm->errmsg == '')
	{
		$vdata['ens'] = $ens;
		$vdata['fm'] = $fm;
		$vdata['mode'] = 'restore';
		$vdata['exec_func'] = 'upload_files';
		$viewfunc = 'view_do_now';
	}
}
// ! uninstall
else if (isset($_POST['uninstall']))
{
	$ens->readProps();
	$fm = get_uploader();
	if ($fm->errmsg == '')
	{
		$vdata['ens'] = $ens;
		$vdata['fm'] = $fm;
		$vdata['mode'] = 'uninstall';
		$vdata['exec_func'] = 'delete_files';
		$viewfunc = 'view_do_now';
	}
}
// ! uninstall addon
else if (isset($_POST['uninstall_addon']))
{
	$ens->readProps();
	$fm = get_uploader();
	if ($fm->errmsg == '')
	{
		$vdata['ens'] = $ens;
		$vdata['fm'] = $fm;
		$vdata['mode'] = 'uninstall';
		$vdata['codename'] = $post['addon_name'];
		$vdata['exec_func'] = 'delete_files';
		$viewfunc = 'view_do_now';
	}
}
// ! move_trydata
else if (isset($_POST['move_trydata']))
{
	$ens->readProps();
	$fm = get_uploader();
	if ($fm->errmsg == '')
	{
		$ens->isMoveTry = TRUE;
		$ens->saveProps();

		$vdata['ens'] = $ens;
		$vdata['fm'] = $fm;
		$vdata['mode'] = 'install';
		$vdata['exec_func'] = 'upload_files';
		$viewfunc = 'view_do_now';
	}
}
// ! set admin data
else if (isset($_POST['set_admin']))
{
	$ens->readProps();
	if ($ens->is_connect())
	{
		$authdata = array();
		$authdata['username'] = trim($_POST['username']);
		$authdata['password'] = trim($_POST['password']);
		$repassword = trim($_POST['re_password']);
		$authdata['admin_email'] = trim($_POST['admin_email']);
		
		if ( ! ctype_alnum($authdata['username'])){
			$error .= 'ユーザー名は、半角英数のみで入力してください<br />';
		}
		if ($authdata['password'] != $repassword){
			$error .= '新パスワードが一致しません<br />';
		}
		if ( ! preg_match(ALLOW_PASSWD_PATTERN , $authdata['password']))
		{
			$error .= 'パスワードは、英数半角と一部の記号のみ(スペース不可)で入力してください<br />';
		}
		if (strlen($authdata['password']) < ALLOW_PASSWD_NUM){
			$error .= 'パスワードは、'.ALLOW_PASSWD_NUM.'文字以上を設定してください<br />';
		}
		
		if ($error == '')
		{
			// FTP情報の暗号化
			if (isset($_SESSION['ftp_info']))
			{
				$fm = new HKN_FTP();
				$fm->readProps();
				$authdata['encrypt_ftp'] = $fm->encrypt_ftp($authdata['username'].$authdata['password']);
			}

			// qhm.ini.php の設定
			if (($error = auth_init($authdata)) === TRUE)
			{
				// メールの送信
				$ens->setProps($authdata);
				$ens->send_mail();

				go_link('install.php?complete&mode=install'); // 完了画面へ
			}
		}
		else
		{
			$vdata['error'] = $error;
			$vdata['email'] = $ens->get_email();
			$viewfunc = 'view_set_admin';
		}
	}
}
// ! replace installer
else if (isset($_GET['replace']))
{
	$ens->readProps();
	if ($ens->is_connect())
	{
		$vdata['ens'] = $ens;
		$viewfunc = 'view_confirm';
	}
}
// ! show set admin view
else if (isset($_GET['admin']))
{
	$ens->readProps();
	if ($ens->is_connect())
	{
		$vdata['error'] = '';
		$vdata['email'] = $ens->get_email();
		$viewfunc = 'view_set_admin';
	}
}
// ! complete
else if (isset($_GET['complete']))
{
	$ens->readProps();
	if ($ens->is_connect())
	{
		if (isset($_SESSION['ensmall_info']))
		{
			unset($_SESSION['ensmall_info']);
		}
		
		$addon = (isset($get['addon']) && $get['addon'] != '');

		$vdata['error'] = '';
		$vdata['mode'] = isset($get['mode']) ? $get['mode'] : '';
		if ($addon)
		{
			$vdata['addon'] = isset($ens->addons[$get['addon']]) ? $ens->addons[$get['addon']]['name'] : '';
		}
		$vdata['myurl'] = $ens->install_url.'?cmd=qhmauth';
		$viewfunc = 'view_do_complete';
		if ($vdata['mode'] != 'uninstall' || $addon)
		{
			$custom_meta = '<meta http-equiv="Refresh" content="15;URL='.$vdata['myurl'].'">';
		}
	}
	
	if (file_exists('install2.php'))
	{
		unlink('install2.php');
	}
}
// ! php check
else
{
	if (isset($_SESSION['ensmall_info']))
	{
		unset($_SESSION['ensmall_info']);
	}

	$pc = new PHPChecker();
	// PHP version Check
	if ( ! $pc->check_php_version())
	{
		$error .= $pc->errmsg;
	} 
	// mbstring_encoding_translation check
	if ( ! $pc->check_encoding('UTF-8'))
	{
		$error .= $pc->errmsg;
	}
	// allow_url_fopen check
	if ( ! $pc->check_ini('allow_url_fopen'))
	{
		$error .= 'arrow_url_fopen を On にしてください';
	}
	
	// safe_mode
	if ( $pc->check_ini('safe_mode'))
	{
		$warning = 'safe_mode が on になっています<br />制限が多いため、正常に動作しない可能性があります';
	}

	$vdata['email'] = '';
	$vdata['error'] = $error;
	$vdata['warning'] = $warning;
	$_SESSION['is_editable'] = $pc->is_editable();
	$viewfunc = 'view_club_login';
}

// ----------------------------------------------------------------------------

/**
* 管理者情報の設定
* 
* @param array data
* @return 
*/
function auth_init($data)
{
	if ( ! file_exists(PRODUCT_CONFIG_FILE))
	{
		return '設定ファイルがありません ['.PRODUCT_CONFIG_FILE.']';
	}
	$str = file_get_contents(PRODUCT_CONFIG_FILE);
	$buff = explode("\n", $str);

	foreach ($buff as $key=>$line)
	{
		if (strpos($line,'$username') === 0)
		{
			$buff[$key] = '$username = "'.$data['username'].'";';
		}
		if (strpos($line,'$passwd') === 0)
		{
			$buff[$key] = '$passwd = "{x-php-md5}'.md5($data['password']).'";';
		}
		if (strpos($line,'$encrypt_ftp') === 0)
		{
			$buff[$key] = '$encrypt_ftp = "'.$data['encrypt_ftp'].'";';
		}
		if (strpos($line,'$admin_email') === 0)
		{
			$buff[$key] = '$admin_email = "'.$data['admin_email'].'";';
		}
	}
	$str = implode("\n", $buff);
	
	if (file_put_contents(PRODUCT_CONFIG_FILE, $str) === FALSE)
	{
		return '設定ファイルに書込みできませんでした ['.PRODUCT_CONFIG_FILE.']';
	}
	chmod(PRODUCT_CONFIG_FILE, 0666);
	
	return TRUE;
}

// ----------------------------------------------------------------------------

/**
* インストーラーのバージョンチェック
* 
* @param class EnsmallAuth
* @param class HokukenFTP or HokukenLocal
* @return string error
*/
function check_installer($ens, $fm)
{
	$error = '';
	if ( ! $ens->check_installer())
	{
		$res = $ens->download('install.php');
		if ($res === ENSMALL_STATUS_ERROR_INSTALL_OVER)
		{
			$error = $ens->errmsg;
		}
		else if ($res)
		{
			// upload file
			if ( ! $fm->upload($res, 'install2.php'))
			{
				$error .= "cannnot upload file:{$file}\n";
			}
			else
			{
				go_link('install2.php?replace');
			}
			$error = 'インストーラーをアップロードできませんでした';
		}
	}

	return $error;
}

// ----------------------------------------------------------------------------

/**
* ファイルのアップロード
* 
* @param string mode (install, update, restore)
* @param class EnsmallAuth
* @param class HokukenFTP or HokukenLocal
* @return string error
*/
function upload_files($mode, $ens, $fm, $codename='')
{
	$error = '';

	// get upload list
	$uplist = $ens->get_updateFileList($mode);
	if ($uplist !== FALSE)
	{
		// make directories
		$fm->mkdirr($uplist['dirs']);
		
		// original data を抽出
		$diff_arr = array();
		foreach ($uplist['originals'] as $regstr)
		{
			$regstr = str_replace("/", "\/", $regstr);
			$regstr = str_replace("*", ".*", $regstr);
			foreach ($uplist['files'] as $file)
			{
				if (preg_match('/^'.$regstr.'$/', $file))
				{
					$diff_arr[$file] = $file;
				}
			}
		}
	
		$sum = 0;
		$trylist = array();
		if ($ens->isMoveTry)
		{
			$ens->setTrySpaceLimit();
			$trylist = $ens->getTrySpaceFileList();
			$sum = count($trylist);
		}
	
		// upload files
		$cnt=0;
		$sum += count($uplist['files']);
		foreach ($uplist['files'] as $file)
		{
			// install.php チェック
			if ($file == 'install.php')
			{
				if (INSTALLER_FILE == 'install.php')
				{
					$cnt++;
					continue;
				}
			}

			// オリジナルデータがなければ作成し、あれば、アップデートしない
			if (array_key_exists($file, $diff_arr) && file_exists($file)) {
				$cnt++;
				continue;
			}
	
			$res = $ens->download($file);
			if ($res === ENSMALL_STATUS_ERROR_INSTALL_OVER)
			{
				$error = $ens->errmsg;
				break;
			}
			if ($res)
			{
				// upload file
				if ( ! $fm->upload($res, $file))
				{
					$error .= "cannnot upload file:{$file}\n";
				}
				else {
					flush2($file, ++$cnt, $sum);
				}
			}
		}

		// 体験スペースの引き継ぎ
		if ($ens->isMoveTry)
		{
			foreach ($trylist as $file)
			{
				if (($res = $ens->download_trySpaceFile($file)) !== FALSE)
				{
					// upload file
					if ( ! $fm->upload($res, $file))
					{
						$error .= "cannnot upload file:{$file}\n";
					}
					else {
						flush2($file, ++$cnt, $sum);
					}
				}
			}
			// download.php を置く
			$ens->putTrySpaceEnd();
		}
	
		// chmod
		$fm->chmodr($uplist['permissions']);
	
		// 利用規約
		$fm->writeDescription($ens->get_description());
		
		// インストール回数をカウントアップ
		$ens->install_log($mode, $fm->server);
	}
	else
	{
		$error = 'ファイルリストを取得できませんでした。';
	}

	if ($error == '')
	{
		if ($mode == 'install')
		{
			go_link('install.php?admin'); // 管理者情報設定へ
		}
		else
		{
			go_link('install.php?complete&mode='.$mode); // 完了画面へ
		}
	}

	return $error;
}


// ----------------------------------------------------------------------------

/**
* ファイルの削除
* 
* @param string mode (install, update, restore)
* @param class EnsmallAuth
* @param string delete codename (''の場合は、アドオンもすべて削除)
* @return string error
*/
function delete_files($mode, $ens, $fm, $codename='')
{
	$error = '';
	$mode = 'uninstall';

	// get upload list
	$uplist = $ens->get_updateFileList($mode, $codename);
	if ($uplist !== FALSE)
	{
		$sum = count($uplist['files']) + count($uplist['dirs']);
		$cnt = 0;
		
		// delete files
		$fm->changeidir();
		foreach($uplist['files'] as $file)
		{
			// install.php チェック
			if ($file == 'install.php')
			{
				$cnt++;
				continue;
			}
			$cnt++;
			$fm->delete_file($file);
			flush2($file, $cnt, $sum);
		}
		
		if ($codename == "")
		{
			// 利用規約の削除
			$fm->delete_file(DESCRIPTION_FILE);
		}
	
		// delete dirs
		$curdir = $fm->pwd();
		foreach($uplist['dirs'] as $file)
		{
			$cnt++;
			$fm->delete_dir($curdir.'/'.$file.'/');
			flush2($file, $cnt, $sum);
		}

		// インストール回数をカウントアップ
		$pid = ($codename == '') ? '' : $ens->addons[$codename]['id'];
		$ens->install_log($mode, $fm->server, $pid);
	}
	else
	{
		$error = 'ファイルリストを取得できませんでした。';
	}

	if ($error == '')
	{
		go_link('install.php?complete&mode='.$mode.'&addon='.$codename);
	}

	return $error;
}


// ----------------------------------------------------------------------------

/**
* プログレス表示
* 
* @param string filename
* @param integer number
* @param integer sum
* @return 
*/
function flush2($file, $num, $sum)
{
	$per = (int) (($num / $sum) * 100);
	echo '
<script type="text/javascript">
<!--
$( "#progressbar" ).progressbar({value: '.$per.'});

$(\'div.complete_file span\').text("'.$file.'");
$(\'span.number\').text("'.$num.'");
$(\'span.total\').text("'.$sum.'");
// -->
</script>';
	flush();
}

// ----------------------------------------------------------------------------

/**
* 設定ファイルの情報を取得
* 
* @param string setting name
* @return string value; 
*/
function get_ini_data($name)
{
	if ( ! file_exists(PRODUCT_CONFIG_FILE))
	{
		return '設定ファイルがありません ['.PRODUCT_CONFIG_FILE.']';
	}
	
	require(PRODUCT_CONFIG_FILE);
	return isset($$name) ? $$name : '';
}

// ----------------------------------------------------------------------------

/**
* ローカル接続かFTP接続かを判定
* 
* @param
* @return class HKN_Local or HKN_FTP 
*/
function get_uploader()
{
	if ($_SESSION['is_editable'])
	{
		$fm = new HKN_Local();
	}
	else
	{
		$fm = new HKN_FTP();
		$fm->readProps();
		$fm->connect();
	}
	
	return $fm;
}

// ----------------------------------------------------------------------------

/**
* 指定したリンクへ移動
* 
* @param string url
* @return 
*/
function go_link($url)
{
	if ($url == '')
	{
		$url = basename(__FILE__);
	}

	echo '<script type="text/javascript">
location.href="'.$url.'";
</script>
';
}

// ----------------------------------------------------------------------------

/**
* Ensmall Club ログイン画面
* 
* @param array $vdata
* @return 
*/
function view_club_login($vdata)
{
	// ! view ensmall club login
	extract($vdata);
?>
<!--login_form start-->
<script type="text/javascript">
<!--
$(document).ready(function(){
	var sa = window.location.href.split('/')
	sa.splice(sa.length-1, 1);
	var url = sa.join('/')+'/';
	$('input:hidden[name=install_url]').val(url);

	
	$('input:checkbox[name=use_proxy]').click(function(){
		if ($(this).is(':checked')) {
			$('div.setproxy').show();
		}
		else {
			$('div.setproxy').hide();
		}
	});
});
//-->
</script>

<form id="UserLoginForm" method="post" action="<?php echo INSTALLER_FILE ?>" class="layoutbox">
<h2>Ensmall Club 認証</h2>
<div class="message"><?php echo $error ?></div>

<?php if (isset($warning) && $warning != '') : ?>
<div class="message"><?php echo $warning ?></div>
<?php endif; ?>

<p class="input"><label>メールアドレス<br />
<input name="email" type="text" size="30" tabindex="1" maxlength="128" value="<?php echo $email?>" id="email" />
</label></p>

<p class="input"><label>パスワード<br />
<input type="password" name="password" size="30" tabindex="2" value="" id="password" />
</label></p>

<br />

<p><input type="hidden" name="use_proxy" value="0" /><label><input type="checkbox" name="use_proxy" value="1" tabindex="3" />プロキシー経由で接続する</label></p>

<div class="setproxy" style="display:none;margin-top:10px;margin-bottom:10px;">
<p class="input"><label>プロキシーホスト<br />
<input name="proxy_host" type="text" size="30" tabindex="4" maxlength="128" value="" id="proxy_host" />
</label></p>
</div>
<br />
<p class="submit"><label><input type="submit" name="club_login" tabindex="5" value="次へ" /></label></p>

<input type="hidden" name="install_url" value="" />
</form>
<!--login_form end-->
<?php
}

// ----------------------------------------------------------------------------

/**
* 管理者ログイン画面
* 
* @param array $vdata
* @return 
*/
function view_admin_login($vdata)
{
	// ! view admin login
	extract($vdata);
?>
<!--admin login_form start-->
<form id="UserLoginForm" method="post" action="<?php echo INSTALLER_FILE ?>" class="layoutbox">
<h2>ユーザー認証</h2>
<div class="message"><?php echo $error ?></div>

<p class="input"><label>管理者 パスワード<br />
<input type="password" name="admin_password" size="30" tabindex="3" value="" id="admin_password" />
</label></p>

<br />
<p class="submit"><label><input type="submit" name="admin_login" tabindex="5" value="ログイン" /></label></p>
</form>
<!--admin login_form end-->
<?php
}

// ----------------------------------------------------------------------------

/**
* FTPログイン画面
* 
* @param array $vdata
* @return 
*/
function view_ftp_login($vdata)
{
	// ! view ftp login
	extract($vdata);
?>
<!--ftp login_form start-->
<form id="UserLoginForm" method="post" action="<?php echo INSTALLER_FILE ?>" class="layoutbox">
<h2>サーバー情報</h2>
<div class="message"><?php echo $error ?></div>

<?php if ($ftp_type == 'full') : ?>
<p class="input"><label>FTPサーバー<br />
<input type="text" name="ftp_hostname" size="30" tabindex="1" maxlength="128" value="localhost" id="ftp_hostname" />
</label></p>
<?php endif; ?>

<p class="input"><label>FTPユーザー (FTPアカウント)<br />
<input type="text" name="ftp_username" size="30" tabindex="2" maxlength="128" value="" id="ftp_username" />
</label></p>

<p class="input"><label>FTPパスワード<br />
<input type="password" name="ftp_password" size="30" tabindex="3" value="" id="ftp_password" />
</label></p>

<?php if ($ftp_type == 'full') : ?>
<p class="input"><label>設置先フォルダ（フルパス）<br />
<input type="text" name="install_dir" size="30" tabindex="4" value="" id="install_dir" />
</label></p>
<?php endif; ?>

<br />
<p class="submit"><label><input type="submit" name="ftp_login" tabindex="5" value="次へ" class="submit" /></label></p>
</form>
<!--ftp login_form end-->
<?php
}

// ----------------------------------------------------------------------------

/**
* 実行確認画面
* 
* @param array $vdata
* @return 
*/
function view_confirm($vdata)
{
	// ! view confirm
	extract($vdata);
	$description = $ens->get_description();
?>
<!--install start-->
<script type="text/javascript">
//<![CDATA[
$(function(){
	$("input:submit").click(function(){
		if ($(this).hasClass('conf_uninstall'))
		{
			var addonname = '';
			if ($(this).closest('form').find('input:hidden[name="addon_jname"]').length)
			{
				addonname = $(this).closest('form').find('input:hidden[name="addon_jname"]').val();
				addonname = addonname + "\n";
			}
			if ( ! confirm(addonname+"アンインストールをしてもよろしいですか？")) {
				return false;
			}
		}

		$(this).attr("disabled", true).addClass("disabled");
		$(this).after('<input type="hidden" name="'+$(this).attr("name")+'" value="1" />');
		$("div.loading").show();
		$(this).closest('form').submit();
	});
});

function agreeCheck(obj)
{
	if (obj.checked) {
		document.getElementById("execBlock").style.display = 'block';
	}
	else {
		document.getElementById("execBlock").style.display = 'none';
	}
}

//]]>
</script>

<div class="layoutbox">

<?php if ($ens->isNew()) : ?>
<h2>インストール</h2>
<?php else : ?>
<h2>システム操作</h2>
<?php endif; ?>

<div class="execute">
<div class="message"><?php echo $error ?></div>

<div id="descriptionBlock">
<textarea readonly="readonly" id="description" cols="30" rows="10" tabindex="1"><?php echo $description?></textarea>
<p style="margin-top:10px;"><label><input type="checkbox" id="agree" onClick="agreeCheck(this)" tabindex="2" />&nbsp;利用規約に同意する</label></p>
</div>

<div id="execBlock" style="display:none">

<form id="ExecuteForm" method="post" action="<?php echo INSTALLER_FILE ?>">

<?php if ($ens->isNew()) : ?>

<?php 	if ($ens->hasTrySpace()) : ?>

<p class="submit"><label><input type="submit" name="move_trydata" tabindex="3" value="体験スペースを引き継ぐ" class="submit" style="float:none" /></label></p>

<p class="submit"><label><input type="submit" name="install" tabindex="4" value="新規インストール" class="submit" style="float:none" /></label></p>

<?php 	else : ?>

<p class="submit"><label><input type="submit" name="install" tabindex="4" value="インストール開始" class="submit" style="float:none" /></label></p>

<?php 	endif; ?>

</form>

<?php else : ?>

<?php 	if ( ! $ens->doRestore()): ?>

<p class="submit"><label><input type="submit" name="update" tabindex="3" value="アップデート" style="float:none;"/></label></p>
<p class="submit2"><label><input type="submit" name="restore" tabindex="4" value="システムの修復" /></label>
<label><input type="submit" name="uninstall" tabindex="5" value="アンインストール" class="conf_uninstall" /></label></p>

<?php 	else : 
	$restore_name = 'システムの修復';
	if ($ens->isQHMTry || $ens->isOpenQHM || $ens->isQHMLite || $ens->isACCafe)
	{
		$restore_name = PRODUCT_JNAME.'へ移行する';
	}
?>
<p class="submit"><label><input type="submit" name="restore" tabindex="4" value="<?php echo $restore_name?>" style="float:none" /></label></p>
<p class="submit2"><label><input type="submit" name="uninstall" tabindex="5" value="アンインストール" class="conf_uninstall" /></label></p>

<?php 	endif; ?>

</form>

<?php	if (count($ens->addons) > 0) : ?>
<hr />

<?php		foreach($ens->addons as $cdname => $row) : 
				if ($row['installed']) : ?>

<form id="ExecuteForm2" method="post" action="<?php echo INSTALLER_FILE ?>">

<p class="submit2"><label><input type="submit" name="uninstall_addon" tabindex="5" value="<?php echo $row['name']?>：アンインストール" class="conf_uninstall" /></label></p>
<input type="hidden" name="addon_name" value="<?php echo $cdname; ?>">
<input type="hidden" name="addon_jname" value="<?php echo h($row['name']); ?>">

</form>
<?php 			endif; ?>
<?php 		endforeach; ?>
<?php	endif; ?>

<?php endif; ?>
</div>

<div class="loading">
<p>現在、実行中です・・・<br />もうしばらくお待ちください。</p>
<p><img src="<?php echo ENSMALL_PRODUCT_URL?>loading.gif" alt="実行中" /></p>
</div>

</div>
</div>
<!--install end-->
<?php
}

// ----------------------------------------------------------------------------

/**
* 実行中の画面
* 
* @param array $vdata
* @return 
*/
function view_do_now($vdata)
{
	// ! view do now
	extract($vdata);
?>
<!-- do now start -->
<p class="message display">サーバーの通信速度によっては、この作業にしばらく時間がかかります。<br />ウィンドウを閉じずにこのままお待ちください。</p>
<div id="process">

<p>実行中です...</p>

<div id="countBlock">
upload・・・　<span class="number"></span>&nbsp;/&nbsp;</span><span class="total"></span>
</div>

<div id="progressbar" style="width:80%;margin:0 auto;text-align:center;"></div>

<div class="complete_file">file : <span></span></div>

</div>
<!-- do now end -->
<?php
	if ($error == '') {
		$codename = isset($codename) ? $codename : '';
		$exec_func($mode, $ens, $fm, $codename);
	}
}

// ----------------------------------------------------------------------------

/**
* 完了画面
* 
* @param array $vdata
* @return 
*/
function view_do_complete($vdata)
{
	// ! view do complete
	extract($vdata);
	
	if ($mode == 'uninstall' && isset($addon) && $addon != '')
	{
		$mode = 'uninstall_addon';
	}
?>
<!-- do complete start-->
<div id="process" class="complete">

<?php if ($mode == 'install') : ?>
<p>インストールと管理者情報の設定が完了しました</p>
<p>ユーザー名、パスワードを入力して<br />ユーザー認証を行うと<br />ページの作成・編集ができます。</p>

<?php elseif ($mode == 'uninstall') : ?>
<p>アンインストールが完了しました。</p>
<p>FTPソフト等を利用して、<br />このファイル（install.php）を削除してください。</p>

<?php elseif ($mode == 'uninstall_addon') : ?>
<p><?php echo $addon; ?> アンインストールが完了しました。</p>

<?php else : ?>
<p>アップデートが完了しました</p>
<?php endif; ?>

<?php if ($mode != 'uninstall') : ?>
<p>5秒後にあなたのサイトに移動します<br />
自動で移動しない場合は、下記のURLをクリックしてください。
</p>

<div>
 <a class="myurl" href="<?php echo $myurl ?>"><?php echo $myurl ?></a>
</div>

<?php endif; ?>

</div>
<!-- do complete end-->
<?php
}

// ----------------------------------------------------------------------------

/**
* 管理者情報入力画面
* 
* @param array $vdata
* @return 
*/
function view_set_admin($vdata)
{
	// ! view set admin data
	extract($vdata);
?>
<!--set_admin start-->
<form id="UserLoginForm" method="post" action="<?php echo INSTALLER_FILE ?>" class="layoutbox">
<h2>管理者情報の設定</h2>
<div class="message"><?php echo $error ?></div>

<p class="input"><label>ユーザー名<br />
<input name="username" type="text" size="30" maxlength="128" value="" id="username" tabindex="1" />
</label></p>

<p class="input"><label>パスワード<br />
<input type="password" name="password" size="30" value="" id="password" tabindex="2" />
</label></p>

<p class="input"><label>パスワード再入力<br />
<input type="password" name="re_password" size="30" value="" id="re_password" tabindex="3" />
</label></p>

<p class="input"><label>メールアドレス<br />
<input name="admin_email" type="text" size="30" maxlength="128" value="<?php echo $email ?>" id="admin_email" class="readonly" readonly="readonly" />
</label></p>

<br />
<p class="submit"><label><input type="submit" name="set_admin" value="完了"  tabindex="4" /></label></p>

</form>
<!--login_form end-->
<?php
}


?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"> 
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="ja" lang="ja"> 
<head>
<meta http-equiv="content-language" content="ja">
<meta charset="UTF-8">
<meta http-equiv="content-type" content="text/html; charset=utf-8" /> 
<meta http-equiv="content-style-type" content="text/css" /> 
<meta http-equiv="Content-Script-Type" content="text/javascript" /> 
<meta name="keywords" content="">
<meta name="description" content="">
<meta name="author" content="HOKUKEN.Inc">
<meta name="copyright" content="copyright HOKUKEN.Inc">
<title><?php echo PRODUCT_NAME ?> Install</title> 
<link type="text/css" href="http://ajax.googleapis.com/ajax/libs/jqueryui/1.8/themes/ui-lightness/jquery-ui.css" rel="stylesheet" />
<script type="text/javascript" src="http<?php echo $_SERVER['SERVER_PORT']==443? 's': ''?>://www.google.com/jsapi"></script>
<script type="text/javascript">
google.load("jquery", "1");
google.load("jqueryui", "1");
</script>
<style type="text/css">
body{
font-family: Arial;
background-color: white;
}
#wrapper{
width: 400px;
margin:0 auto;
text-align: center;
display: block;
}
#header h1{
font-size: 150%;
text-align: right;
font-family: 'Muli', sans-serif;
}
#footer {
text-align: right;
padding:10px 0;
}
#content{
display: block;
margin: 16px auto 0px;
text-align: left;
}
#content .layoutbox{
position:relative;
padding: 10px 10px 10px 16px;
background-color: white;
border: 1px solid #eee;
border-radius: 10px;
-moz-box-shadow: rgba(200, 200, 200, 1) 0 4px 18px;
-webkit-box-shadow: rgba(200, 200, 200, 1) 0 4px 18px;
-khtml-box-shadow: rgba(200, 200, 200, 1) 0 4px 18px;
box-shadow: rgba(200, 200, 200, 1) 0 4px 18px;
display: block;
}
#content h2{
font-size: 120%;
text-align: center;
}
form p{
margin: 0;
}
label {
color: #666;
}
.input input{
font-size: 20px;
height: 30px;
width: 97%;
padding: 3px;
margin-top: 2px;
margin-right: 6px;
margin-bottom: 16px;
border: 1px solid #E5E5E5;
background: #FBFBFB;
color: #333;
}
form .readonly {
font-size: 16px;
height: 30px;
width: 97%;
padding: 3px;
margin-top: 2px;
margin-right: 6px;
margin-bottom: 16px;
border: 1px solid #E5E5E5;
background: #eee;
}
.submit input{
color: #fff;
-moz-border-radius: 5px;
-webkit-border-radius: 5px;
border-radius: 5px;
background: #BFD255;
background: -moz-linear-gradient(top, #BFD255 0%, #8EB92A 50%, #72AA00 51%, #9ECB2D 100%);
background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#BFD255), color-stop(50%,#8EB92A), color-stop(51%,#72AA00), color-stop(100%,#9ECB2D));
display: inline;
margin: 0 0 10px;
height:32px;
font-size:16px;
float:right;
padding: 0px 20px;
}
.submit label{
display: block;
height: 40px;
}
.submit2 input{
color: #fff;
-moz-border-radius: 5px;
-webkit-border-radius: 5px;
border-radius: 5px;
background: #eee;
background: -moz-linear-gradient(top, #999 0%, #777 50%, #666 51%, #999 100%);
background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#999), color-stop(50%,#777), color-stop(51%,#666), color-stop(100%,#999));
display: inline;
margin: 0 0 10px;
height:28px;
font-size:13px;
padding: 0px 20px;
}
.message{
color: red;
font-size: 90%;
padding: 5px;
text-align: center;
}
#process{
border: 1px solid #afafaf;
-moz-border-radius: 10px;
-webkit-border-radius: 10px;
border-radius: 10px;
background-color: #eee;
text-align: center;
font-size: 100%;
padding: 10px 0;
}
#process img{
padding-top: 10px;
}
#process ul {
padding: 10px;
margin: 0;
text-align: left;
}
#process ul li{
font-size: 90%;
list-style: none;
display: block;
margin: 0 0 0 5px;
padding: 2px;
}
.complete{
line-height: 1.7em;
}
.display{
display: block;
}
#descriptionBlock textarea{
font-size: 12px;
width:97%;
}
#execBlock p{
margin:1.2em 0;
text-align: center;
}
div.complete_file{
margin:0;
padding: 10px;
text-align: left;
overflow: hidden;
}
input.disabled{
background: none;
background-color:#ccc;
}
div.loading{
display:none;
width:300px;
line-height: 1.5em;
position:absolute;
top:50%;
left:30px;
border: 3px solid #99CC33;
-moz-border-radius: 10px;
-webkit-border-radius: 10px;
border-radius: 10px;
padding: 10px 10px 10px 16px;
background-color: white;
border-radius: 10px;
-moz-box-shadow: rgba(100, 100, 100, 1) 0 4px 200px;
-webkit-box-shadow: rgba(100, 100, 100, 1) 0 4px 200px;
-khtml-box-shadow: rgba(100, 100, 100, 1) 0 4px 200px;
box-shadow: rgba(100, 100, 100, 1) 3px 4px 200px;
text-align: center;
}
</style>
<?php
if (isset($custom_meta))
{
	echo $custom_meta;
}
?>
</head> 
<body> 
<div id="wrapper">

<div id="header">
  <h1><?php echo h(PRODUCT_NAME); ?></h1>
</div>

<div id="content">
<?php if( isset($viewfunc) && function_exists($viewfunc)){ $viewfunc($vdata); } else { echo 'No View '; } ?>
</div>

<div id="footer">
hokuken.Inc &copy;
</div>

</div>
</body>
</html>