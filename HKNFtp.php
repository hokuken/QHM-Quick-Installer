<?php
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
