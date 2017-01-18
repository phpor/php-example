<?php
// 参考资料： 
// http://blog.chinaunix.net/uid-26366978-id-3282793.html
// http://www.2cto.com/net/201305/216076.html
// http://www.roman10.net/2011/11/27/how-to-calculate-iptcpudp-checksumpart-1-theory/
// 注意事项：
// 1. 伪头部的概念，tcp的checksum只包含ip头部的部分信息，不包含ttl、ip checksum、ip标识、ip片偏移等信息，因为这些是包传输过程中动态变化的
// 2. php 提供的raw socket只是允许ip层以上的自定义封包，ip层的封包是无法随意定义的，只能定义上层协议号信息，也因此我们并不需要关心ip层checksum的计算
// 3. 虽然该脚本中不想知道ip源地址，只是tcp的checksum需要该信息，所以才允许传参的（否则自动发现eth0）
// 4. 注意tcp checksum的算法
// 5. 关于本地端口的选择，这里先bind了一下，避免和影响已有的连接（应该这个逻辑并非多此一举吧）
// 6. 原本意味收到远端的syn-ack之后需要发送一个rst，避免远端等待我的ack（猜测通过简单的close应该可以实现）； 测试发现，当本机收到远端响应的syn-ack之后，系统立即发送了一个rst包（不知道为什么）？？？？可能是我们的脚本哪里出了问题

define("TCP_FLAG_FIN", 0x01);
define("TCP_FLAG_SYN", 0x02);
define("TCP_FLAG_RST", 0x04);
define("TCP_FLAG_PSH", 0x08);
define("TCP_FLAG_ACK", 0x10);
define("TCP_FLAG_URG", 0x20);

$ip = $argv[1];
$port = $argv[2];
$source_ip = $argv[3];
$cmdip = <<<eof
ifconfig eth0|grep "inet addr:"|awk -F":" '{print $2}' |awk '{print $1}'
eof
;

if(!$source_ip) {
	$source_ip = exec($cmdip);
}
synprobe($source_ip, $ip, $port);
function synprobe($source_ip, $dst_ip, $port) {
	$socket = socket_create(AF_INET, SOCK_RAW, SOL_TCP);
	socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array("sec" => 1, "usec" => 0));

	while(true) {
		$sport = select_sport();
		$ret = socket_bind($socket, $source_ip, $port);
		if($ret) break;
	}
	socket_connect($socket, $dst_ip, null);
	$dport = $port;
	$packet_syn = make_packet_syn($source_ip, $sport, $dst_ip, $dport);
	$start_time = microtime(1);
	socket_send($socket, $packet_syn, strlen($packet_syn), 0);

	if($result = @socket_read($socket, 255)) {
		$p = parse_packet($result);
		if(($p["tcp"]["flag"] & TCP_FLAG_RST) === TCP_FLAG_RST) {
			echo "CLOSED";
		} else if(($p["tcp"]["flag"] & TCP_FLAG_ACK) === TCP_FLAG_ACK) {
			echo "OPENED";
		} else {
			print_r($p);
		}
	} else {
		echo "timeout";
	}
	echo "\n";
	$end_time = microtime(1);
	socket_close($socket);
}
function select_sport() {
	#return 55555;
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

function make_packet_syn($source_ip, $sport, $dst_ip, $dport, $with_checksum = true) {
	$format = "nnNNCCnnn";
	$sn = 0x0000;
	$ack_number = 0x0000;
	$header_length = 0x06 << 4;
	$flag = 0x02;
	$window_size = 0xffff;
	if ($with_checksum) {
		$checksum = calc_check_sum($source_ip, $sport, $dst_ip, $dport);
	} else {
		$checksum = 0x00;
	}
	$ur = 0x00;
	$option = pack("CCn", 0x02, 0x04, 1460);
	$basic = pack($format, $sport, $dport, $sn, $ack_number, $header_length, $flag, $window_size, $checksum, $ur);
	return $basic.$option;
}
function make_pseudo_header($source_ip, $sport, $dst_ip, $dport) {
	$ip_header_format = "NNCCn";
	$long_source_ip = ip2long($source_ip);
	$long_dst_ip = ip2long($dst_ip);
	$zero = 0x0;
	$protol = SOL_TCP;
	$ip_data_length = 0x6*4;
	$packet_ip = pack($ip_header_format, $long_source_ip, $long_dst_ip, $zero, $protol, $ip_data_length);
	$packet_tcp = make_packet_syn($source_ip, $sport, $dst_ip, $dport, false);
	return $packet_ip. $packet_tcp;
}
function calc_check_sum($source_ip, $sport, $dst_ip, $dport) {
	$pseudo_header = make_pseudo_header($source_ip, $sport, $dst_ip, $dport);
	$checksum = 0x0000;
	$arr = unpack("n*", $pseudo_header);
	foreach($arr as $int) {
		$checksum += $int;
	}
	while (($checksum & 0xffff0000) != 0) {
		$checksum = (($checksum >> 16) & 0x0000ffff) + ($checksum & 0x0000ffff);
	}
	$checksum =  ~$checksum & 0x0000ffff;
	return $checksum;
}
/**
  ip header:
	C: 1 ver_and_len
	C: 1 tos
	N: 4 len
	N: 4 identifier
	N: tag_and_offset
	C: 1 ttl
	C: 1 protocol
	N: 4 checksum
	N: 4 source_ip
	N: 4 dst_ip
*/
function parse_packet($packet) {
	$ip_header = substr($packet, 0, 20);
	$tcp_header = substr($packet, 20, 24);
	$ip_format = "Cver_and_len/Ctos/nlen/nident/ntag_and_offset/Cttl/Cprotocol/nchecksum/Nsource_ip/Ndst_ip";
	$arr_ip = unpack($ip_format, $ip_header);
	$tcp_format = "nsrc_port/ndst_port/Nseq/Nack/Clen/Cflag/nwin/nchecksum/nur";
	$arr_tcp = unpack($tcp_format, $tcp_header);
	$tcp_flag = substr($tcp_header, 17, 1);

	$arr_ip["source_ip"] = long2ip($arr_ip["source_ip"]);
	$arr_ip["dst_ip"] = long2ip($arr_ip["dst_ip"]);

	return array("ip"=>$arr_ip, "tcp" => $arr_tcp);
}
