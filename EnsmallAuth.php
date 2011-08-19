<?php 
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
