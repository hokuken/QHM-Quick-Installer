#!/usr/bin/php
<?php

$dir = dirname(__FILE__);
$curdir = getcwd();
if ($dir != $curdir)
{
	die('実行フォルダが不正です。'. $curdir);
}
//chdir(dirname(dirname(__FILE__)). '/installer/');

$installer_src = file_get_contents('index.php');
$ptn = "/\nrequire\('([\w.]+)'\);/";
if (preg_match_all($ptn, $installer_src, $mts))
{
	$cnt = 0;
	foreach ($mts[1] as $filename)
	{
		echo $filename. " reading...\n";
		$file_src = file_get_contents($filename);
		$file_src = preg_replace(array('/^<'.'\?php/', '/\?'.'>$/'), array('', ''), trim($file_src));
		$installer_src = str_replace($mts[0][$cnt], $file_src, $installer_src);
		$cnt++;
	}
	file_put_contents('tmp.php', $installer_src);
}
system('cp tmp.php install2.php');
system('php -w tmp.php > install.php');
unlink('tmp.php');

echo 'finished!'. "\n";
