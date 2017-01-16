<?php
$ip = $argv[1];
$port = $argv[2];
#echo "$ip:$port";
synprobe($ip, $port);
function synprobe($ip, $port) {
	$socket = socket_create(AF_INET, SOCK_RAW, SOL_TCP);
	socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array("sec" => 1, "usec" => 0));
	socket_connect($socket, $ip, null);

	$sport = select_sport();
	$dport = $port;
	$packet_syn = make_packet_syn($sport, $dport);
	$start_time = microtime(1);
	socket_send($socket, $packet_syn, strlen($packet_syn), 0);

	if($result = @socket_read($socket, 255)) {
		$p = parse_packet($result);
	} else {

	}
	$end_time = microtime(1);
	socket_close($socket);
}
function select_sport() {
	return rand(55000, 56000);
}
/**
 n: 2 source port
 n: 2 dest port
 N: 4 sequence number 0x0000
 N: 4 acknowlegedment number 0x0000
 C: 1 header length 20 (only four bits)
 C: 1 tcp flag 0x02
 n: 2 windows size 0xffff
 n: 2 checksum 0x00
 n: 2 urgent pointer 0x00
*/

function make_packet_syn($sport, $dport) {
	$format = "nnNNCCnnn";
	$sn = 0x0000;
	$ack_number = 0x0000;
	$header_length = 0x05 << 4;
	$flag = 0x02;
	$window_size = 0xffff;
	$checksum = 0x00;
	$ur = 0x00;
	$ret = pack($format, $sport, $dport, $sn, $ack_number, $header_length, $flag, $window_size, $checksum, $ur);
	return $ret;
}
function parse_packet($packet) {

}
