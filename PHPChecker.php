<?php
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
