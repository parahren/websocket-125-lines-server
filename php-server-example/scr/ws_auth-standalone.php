<?php

//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
//#
//# websocket demo server
//#
//# by par.ahren@infrasec.se 2013-03-20
//#
//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

date_default_timezone_set("Europe/Stockholm");
require_once("printHexDump.php");

//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
//# SET PARAMS
//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
$HTTP_REQ_KEY      = "Sec-WebSocket-Key: ";
$GUID_STRING  = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
$HTTP_REQ_END = "\r\n\r\n";

$sockCount    = 0;
$address      = '0.0.0.0';
$port         = 8080;

//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
//# Create a new normal BSD-socket
//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
if (($sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) === false)
{
    printf("socket_create() failed: reason: " . socket_strerror(socket_last_error()) . "\n");
    die(1);
}

if (socket_bind($sock, $address, $port) === false)
{
    printf("socket_bind() failed: reason: " . socket_strerror(socket_last_error($sock)) . "\n");
    die(1);
}

if (socket_listen($sock, 5) === false)
{
    printf("socket_listen() failed: reason: " . socket_strerror(socket_last_error($sock)) . "\n");
    die(1);
}


//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
//# Lets start the loop where we Listen to a port and transfer data...
//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
while(1)
{
	//# Count connections
	$sockCount++;

	//#########################################################################
	printf("\n");
	printf("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
	printf("#%02.2d: Server Listening on $address:$port\n", $sockCount);
	//#########################################################################

	//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
	//# LISTEN on port
	//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
	if(false !== ($c = socket_accept($sock)))
	{
		//#########################################################################
		printf("#%02.2d: Server Accepted connnection\n", $sockCount);
		//#########################################################################

		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//# NOW THE WEBSOCKET CODE STARTS !!!
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//# WS00: GET Websocket HTTP-header
		//# (No options here we will only accept ws)
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		$loop = true;
		$httpHeader = "";
		while ($loop == true)
		{
			$char = socket_read($c, 1);

			if($char !== false)
			{
				$httpHeader .= $char;

				//# Check if last four charachters in string is "CRLNCRLN":
				if(strcmp($HTTP_REQ_END, substr($httpHeader, -4)) == 0)
				{
					//# YES! Then we are done here!!!
					$loop = false;
				}
			}
			else
			{
				//# Error data missing....
				die(1);
			}
		}

		//#########################################################################
		printf("#%02.2d: HTTP-request header:\n", $sockCount);
		printf("'".$httpHeader."'\n");
		//#########################################################################

		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//# WS01: Get challange out of HTTP-header request
		//# (we skip the rest of the parameters to make this example small...)
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//# Example data sent from a Chrome client:
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//# GET / HTTP/1.1
		//# Upgrade: websocket
		//# Connection: Upgrade
		//# Host: 127.0.0.1:8080
		//# Origin: null
		//# Pragma: no-cache
		//# Cache-Control: no-cache
		//# Sec-WebSocket-Key: G+10stsF1ot+SNwsDdf1lw==			<==== THIS
		//# Sec-WebSocket-Version: 13
		//# Sec-WebSocket-Extensions: x-webkit-deflate-frame
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//# Find position of key
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		$HttpReqKey = strpos($httpHeader, $HTTP_REQ_KEY);
		if ($HttpReqKey === false)
		{
			//#########################################################################
			printf("#%02.2d", $sockCount);
			printf("Can't find: '$HTTP_REQ_KEY'\n");
Die(1);
			//#########################################################################
		}

		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//# Get "challange" value: "G+10stsF1ot+SNwsDdf1lw=="
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		$ValueStartPos = ($HttpReqKey + strlen($HTTP_REQ_KEY));
		$CutBefore     = substr($httpHeader, $ValueStartPos);
		$ValueEndPos   = strpos($CutBefore, "\r");

		if ($ValueEndPos === false)
		{
			//#########################################################################
			printf("#%02.2d", $sockCount);
			printf("NO 'CR'-char !!!\n");
			die(1);
//#########################################################################
		}
		$challenge = substr($CutBefore, 0, $ValueEndPos);

		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//# WS02: Concat challenge with static guid
		//#
		//# response = base64(sha1($CHALLANGE + $GUID_STRING))
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		$response_base = $challenge.$GUID_STRING;
		$response = base64_encode(sha1($response_base, true));

		socket_write($c, "HTTP/1.1 101 Switching Protocols\r\n");
		socket_write($c, "Upgrade: websocket\r\n");
		socket_write($c, "Connection: Upgrade\r\n");
		socket_write($c, "Sec-WebSocket-Accept: ");
		socket_write($c, $response);
		socket_write($c, "\r\n\r\n");

		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//# Now we have a authenticated socket to play with!!!
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//# WS03: Send a message to client
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		$respMessAsciiText = "Hi this is the websocket-server in PHP!\r\nby par.ahren@infrasec.se\r\n";
		$respMessEncoded = base64_encode(utf8_encode($respMessAsciiText));
		$respMessEncodedLen = strlen($respMessEncoded);

		if($respMessEncodedLen < 0x7d)
		{
			//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
			//# Data encoding
			//#------------------------------------------------------------------------
			//# See: http://tools.ietf.org/html/rfc6455
			//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
			//# 5.7.  Examples
			//#
			//# o  A single-frame unmasked text message
			//#
			//# *  0x81 0x05 0x48 0x65 0x6c 0x6c 0x6f (contains "Hello")
			//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
			//# 0x81 -  0x?1 
			//# 0x05 -  0xNN characters
			//# 0x48 -  "H"
			//# 0x65 -  "e"
			//# 0x6c -  "l"
			//# 0x6c -  "l"
			//# 0x6f -  "o"
			//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

			$sndData = "";
			$sndData .= chr(0x81);
			$sndData .= chr($respMessEncodedLen);
			$sndData .= $respMessEncoded;
		}
		else
		{
			//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
			//# 5.2.  Base Framing Protocol
			//# ...
			//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
			//# frame-payload-length
			//# = ( %x00-7D )
			//#    / ( %x7E frame-payload-length-16 )
			//#    / ( %x7F frame-payload-length-63 )
			//#    ; 7, 7+16, or 7+64 bits in length,
			//#    ; respectively
			//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

			//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
			//# NOT IMPL.
			//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
			die(1);
		}
		socket_write($c, $sndData);


		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//# WS04: For now we will get some data, then end ...
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//#########################################################################
		printf("#%02.2d: Waiting for client to send data\n", $sockCount);
		//#########################################################################

		$getData = "";
		$getData = socket_read($c, 10000);

		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		//# WS05: Decode data
		//# (There are a bit of data crunshing needed to get it in clear...)
		//#------------------------------------------------------------------------
		//# See more "http://tools.ietf.org/html/rfc6455"
		//# "5.2.  Base Framing Protocol"
		//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
		if(empty($getData) !== true)
		{
			//# Ignore hi-bit (maybe use two different checks "0x7e" or "0xfe")
			$lengthCode = ord($getData[1]) & 127;

			//#########################################################################
			printf("#%02.2d: ", $sockCount);
			//#########################################################################

			if($lengthCode < 0x7e)
			{
				//#########################################################################
				printf("Length-Type=1\n");
				//#########################################################################

				//# Not used in this case...
				$binLen = "";
				$mask = substr($getData, 2, 4);
				$msg  = substr($getData, 6);

				//# The code is the length ...
				$dataLength = $lengthCode;
			}
			elseif($lengthCode == 0x7e)
			{
				//#########################################################################
				printf("Length-Type=2\n");
				//#########################################################################

				$binLen = substr($getData, 2, 2);
				$mask   = substr($getData, 4, 4);
				$msg    = substr($getData, 8);

				//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
				//# n	unsigned short (always 16 bit, big endian byte order)
				//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
				//# PHP-magic... Convert two binary-chars to an "UNSIGNED SHORT"
				//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
				list($dataLength) = array_values(unpack('n', $binLen));
			}
			elseif($lengthCode == 0x7f)
			{
				//#########################################################################
				printf("Length-Type=3\n");
				//#########################################################################

				$binLen = substr($getData, 2, 4);
				$mask   = substr($getData, 8, 4);
				$msg    = substr($getData, 12);

				//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
				//# N	unsigned long (always 32 bit, big endian byte order)
				//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
				//# PHP-magic... Convert four binary-chars to an "UNSIGNED LONG"
				//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
				list($dataLength) = array_values(unpack('N', $binLen));
			}
			else
			{
				//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
				//# ERROR: ???
				//#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

				//#########################################################################
				printf("ERROR: lengthCode='0x".dechex(ord($lengthCode))."'\n");
				//#########################################################################

				die(1);
			}

			//#########################################################################
			printf("#%02.2d: DATALEN=%s\n", $sockCount, $dataLength);
			//#########################################################################

			//# printf("binLen");
			//# printHexDump($binLen);
			//# printf("--------------------------------------------------------\n");

			//# printf("getData");
			//# printHexDump($getData);
			//# printf("--------------------------------------------------------\n");

			//# printf("mask");
			//# printHexDump($mask);
			//# printf("--------------------------------------------------------\n");

			//# printf("msg");
			//# printHexDump($msg);
			//# printf("--------------------------------------------------------\n");

			//#########################################################################
			printf("#%02.2d: DATA:\n", $sockCount);
			printf("'");
			//#########################################################################

			//#---------------------------------
			//# Un-mask the data
			//#---------------------------------
			$jj = 0;
			for ($ii = 0; $ii < strlen($msg); $ii++)
			{
				//# XOR with mask
				$unMasked = ($msg[$ii] ^ $mask[$jj]);
				//#########################################################################
				printf($unMasked);
				//#########################################################################

				//# The mask is 4 charachters (0 -- 3)
				$jj = (++$jj % 4);
			}

			//#########################################################################
			printf("'\n");
			//#########################################################################
		}
		else
		{
			//#########################################################################
			printf("#%02.2d", $sockCount);
			printf("NO DATA!\n");
die(9);
			//#########################################################################
		}


		//#------------------------------------------------------------------
		//# I am tired now so lets close this socket ... :)
		//#------------------------------------------------------------------
		//#########################################################################
		printf("#%02.2d: Closing socket\n", $sockCount);
		printf("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
		printf("\n\n\n");
		//#########################################################################

		socket_close($c);
	}
}

//#------------------------------------------------------------------
//# We will nerver get to this when using "while(1)"
//# But it looks good... or ... not .... ;)
//#------------------------------------------------------------------
socket_close($socket);


