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


require('post.php');
require('Mcrypt.php');
require('Ftp.php');
require('HKNFtp.php');
require('HKNLocal.php');
require('PHPChecker.php');
require('EnsmallAuth.php');


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
		// need ftp login
		if ( ! $_SESSION['is_editable'])
		{
			if ($ens->isNew()) {
				$vdata['ftp_type'] = 'default';
				$viewfunc = 'view_ftp_login';
			}
			else {
				// Update or Uninstall or Reset Password
				$viewfunc = 'view_admin_login';
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
	else {
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
		
		if ($error != '')
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
<input name="email" type="text" size="30" tabindex="1" maxlength="128" value="" id="email" />
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
<p class="message display">サーバーの通信速度によっては、この作業にしばらく時間がかかります。<br />ウィンドウを閉じずにこのままでお待ちください。</p>
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