<?php
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
