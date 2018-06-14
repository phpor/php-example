<?php

function multi_cmd($arr) {
	$arrResult = array();
	$arrFp = array();
	foreach($arr as  $k => $cmd) {
		$arrFp[$k] = popen($cmd, "r");
		if(!$arrFp[$k]) {
			$arrResult[$k] = array("stdout" => null, "meta"=>array("elapse"=>0));
			unset($arrFp[$k]);
			continue;
		}
		stream_set_blocking($arrFp[$k], false);
	}
	$start = microtime(1);
	$write = null;
	$expect = null;
	while(count($arrFp) > 0) {
		$arrRead = array_values($arrFp);
		$ret = stream_select($arrRead, $write, $expect, 0, 200000);
		if($ret === false) break;
		if($ret === 0) continue;
		foreach($arrFp as $k=>$fp) {
			if (!in_array($fp, $arrRead)) continue;
			while(!feof($fp)) {
				$r = fread($fp, 1024);
				if ($r !== "" && $r !== false) $arrResult[$k]["stdout"] .= $r;
				if (feof($fp) || $r === false) {
					unset($arrFp[$k]);
					$arrResult[$k]["meta"]["elapse"] = microtime(1) - $start;
					break;
				}
				if ($r === "") break;
			}
		}
	}
	return $arrResult;
}

/**
$arr = array(
	"cmd1" => "sleep 1; eacho 1",
	"cmd2" => "sleep 2; echo 2",
	"cmd3" => "sleep 3; echo 3",
);
$arrResult = multi_cmd($arr);
print_r($arrResult);
*/
