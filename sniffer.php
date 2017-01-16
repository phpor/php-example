<?php
/**
    from: http://www.binarytides.com/code-a-packet-sniffer-in-php/
    Packet sniffer in PHP
    Will run only on Linux
    Needs root privileges , so use sudo !!
*/

error_reporting(~E_ALL);

//Create a RAW socket
$socket = socket_create(AF_INET , SOCK_RAW , SOL_TCP);
if($socket)
{
    echo "Starting sniffing...\n";
    while(true)
    {
        //Start receiving on the raw socket
        socket_recv ( $socket , $buf , 65536 , 0 );

        //Process the packet
        process_packet($buf);
    }
}

//Some error - check that you used sudo !!
else
{
    $error_code = socket_last_error();
    $error_message = socket_strerror($error_code);

    echo "Could not create socket : [$error_code] $error_message";
}

/**
    Process the captured packet.
*/
function process_packet($packet)
{
    //IP Header
    $ip_header_fmt = 'Cip_ver_len/'
    .'Ctos/'
    .'ntot_len/'
    .'nidentification/'
    .'nfrag_off/'
    .'Cttl/'
    .'Cprotocol/nheader_checksum/Nsource_add/Ndest_add/';

    //Unpack the IP header
    $ip_header = unpack($ip_header_fmt , $packet);

    if($ip_header['protocol'] == '6')
    {
        print_tcp_packet($packet);
    }
}

/*
  Process a TCP Packet :)
*/
function print_tcp_packet($packet)
{
    $ip_header_fmt = 'Cip_ver_len/'
    .'Ctos/'
    .'ntot_len/';

    $p = unpack($ip_header_fmt , $packet);
    $ip_len = ($p['ip_ver_len'] & 0x0F);

    if($ip_len == 5)
    {

        //IP Header format for unpack
        $ip_header_fmt = 'Cip_ver_len/'
        .'Ctos/'
        .'ntot_len/'
        .'nidentification/'
        .'nfrag_off/'
        .'Cttl/'
        .'Cprotocol/'
        .'nip_checksum/'
        .'Nsource_add/'
        .'Ndest_add/';
    }
    else if ($ip_len == 6)
    {
        //IP Header format for unpack
        $ip_header_fmt = 'Cip_ver_len/'
        .'Ctos/'
        .'ntot_len/'
        .'nidentification/'
        .'nfrag_off/'
        .'Cttl/'
        .'Cprotocol/'
        .'nip_checksum/'
        .'Nsource_add/'
        .'Ndest_add/'
        .'Noptions_padding/';
    }

    $tcp_header_fmt = 'nsource_port/'
    .'ndest_port/'
    .'Nsequence_number/'
    .'Nacknowledgement_number/'
    .'Coffset_reserved/';

    //total packet unpack format
    $total_packet = $ip_header_fmt.$tcp_header_fmt.'H*data';

    $p = unpack($total_packet , $packet);
    $tcp_header_len = ($p['offset_reserved'] >> 4);

    if($tcp_header_len == 5)
    {
        //TCP Header Format for unpack
        $tcp_header_fmt = 'nsource_port/'
        .'ndest_port/'
        .'Nsequence_number/'
        .'Nacknowledgement_number/'
        .'Coffset_reserved/'
        .'Ctcp_flags/'
        .'nwindow_size/'
        .'nchecksum/'
        .'nurgent_pointer/';
    }
    else if($tcp_header_len == 6)
    {
        //TCP Header Format for unpack
        $tcp_header_fmt = 'nsource_port/'
        .'ndest_port/'
        .'Nsequence_number/'
        .'Nacknowledgement_number/'
        .'Coffset_reserved/'
        .'Ctcp_flags/'
        .'nwindow_size/'
        .'nchecksum/'
        .'nurgent_pointer/'
        .'Ntcp_options_padding/';
    }

    //total packet unpack format
    $total_packet = $ip_header_fmt.$tcp_header_fmt.'H*data';

    //unpack the packet finally
    $packet = unpack($total_packet , $packet);

    //prepare the unpacked data
    $sniff = array(

        'ip_header' => array(
            'ip_ver' => ($packet['ip_ver_len'] >> 4) ,
            'ip_len' => ($packet['ip_ver_len'] & 0x0F) ,
            'tos' => $packet['tos'] ,
            'tot_len' => $packet['tot_len'] ,
            'identification' => $packet['identification'] ,
            'frag_off' => $packet['frag_off'] ,
            'ttl' => $packet['ttl'] ,
            'protocol' => $packet['protocol'] ,
            'checksum' => $packet['ip_checksum'] ,
            'source_add' => long2ip($packet['source_add']) ,
            'dest_add' => long2ip($packet['dest_add']) ,
        ) ,

        'tcp_header' => array(
            'source_port' => $packet['source_port'] ,
            'dest_port' => $packet['dest_port'] ,
            'sequence_number' => $packet['sequence_number'] ,
            'acknowledgement_number' => $packet['acknowledgement_number'] ,
            'tcp_header_length' => ($packet['offset_reserved'] >> 4) ,

            'tcp_flags' => array(
                'cwr' => (($packet['tcp_flags'] & 0x80) >> 7) ,
                'ecn' => (($packet['tcp_flags'] & 0x40) >> 6) ,
                'urgent' => (($packet['tcp_flags'] & 0x20) >> 5 ) ,
                'ack' => (($packet['tcp_flags'] & 0x10) >>4) ,
                'push' => (($packet['tcp_flags'] & 0x08)>>3) ,
                'reset' => (($packet['tcp_flags'] & 0x04)>>2) ,
                'syn' => (($packet['tcp_flags'] & 0x02)>>1) ,
                'fin' => (($packet['tcp_flags'] & 0x01)) ,
            ) ,

            'window_size' => $packet['window_size'] ,
            'checksum' => $packet['checksum'] . ' [0x'.dechex($packet['checksum']).']',
        ) ,

        'data' => hex_to_str($packet['data'])
    );

    //print the unpacked data
    print_r($sniff);
}

/*
    idea taken from http://ditio.net/2008/11/04/php-string-to-hex-and-hex-to-string-functions/
    modified a bit to show non alphanumeric characters as dot.
*/
function hex_to_str($hex)
{
    $string='';

    for ($i=0; $i < strlen($hex)-1; $i+=2)
    {
        $d = hexdec($hex[$i].$hex[$i+1]);

        //Show only if number of alphabet
        if( ($d >= 48 and $d <= 57) or ($d >= 65 and $d <= 90) or ($d >= 97 and $d <= 122) )
        {
            $string .= chr(hexdec($hex[$i].$hex[$i+1]));
        }
        else
        {
            $string .= '.';
        }
    }

    return $string;
}
