<?php
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
	
	var $server = '';
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
