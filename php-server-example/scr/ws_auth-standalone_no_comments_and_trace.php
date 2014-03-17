<?php
date_default_timezone_set("Europe/Stockholm");
$HTTP_REQ_KEY = "Sec-WebSocket-Key: ";
$GUID_STRING  = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
$HTTP_REQ_END = "\r\n\r\n";
$sockCount    = 0;
$address      = '0.0.0.0';
$port         = 8080;
if (($sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) === false)
{
    die(1);
}
if (socket_bind($sock, $address, $port) === false)
{
    die(2);
}
if (socket_listen($sock, 5) === false)
{
    die(3);
}
while(1)
{
	$sockCount++;
	if(false !== ($c = socket_accept($sock)))
	{
		$loop = true;
		$httpHeader = "";
		while ($loop == true)
		{
			$char = socket_read($c, 1);
			if($char !== false)
			{
				$httpHeader .= $char;
				if(strcmp($HTTP_REQ_END, substr($httpHeader, -4)) == 0)
				{
					$loop = false;
				}
			}
			else
			{
				die(4);
			}
		}
		$HttpReqKey = strpos($httpHeader, $HTTP_REQ_KEY);
		if ($HttpReqKey === false)
		{
			die(5);
		}
		$ValueStartPos = ($HttpReqKey + strlen($HTTP_REQ_KEY));
		$CutBefore     = substr($httpHeader, $ValueStartPos);
		$ValueEndPos   = strpos($CutBefore, "\r");
		if ($ValueEndPos === false)
		{
			die(6);
		}
		$challenge = substr($CutBefore, 0, $ValueEndPos);
		$response_base = $challenge.$GUID_STRING;
		$response = base64_encode(sha1($response_base, true));
		socket_write($c, "HTTP/1.1 101 Switching Protocols\r\n");
		socket_write($c, "Upgrade: websocket\r\n");
		socket_write($c, "Connection: Upgrade\r\n");
		socket_write($c, "Sec-WebSocket-Accept: ");
		socket_write($c, $response);
		socket_write($c, $HTTP_REQ_END);
		$respMessAsciiText = "Hi this is the websocket-server in PHP talking!\r\n(by par.ahren@infrasec.se)\r\n";
		$respMessEncoded = base64_encode(utf8_encode($respMessAsciiText));
		$respMessEncodedLen = strlen($respMessEncoded);
		if($respMessEncodedLen < 0x7d)
		{
			$sndData = "";
			$sndData .= chr(0x81);
			$sndData .= chr($respMessEncodedLen);
			$sndData .= $respMessEncoded;
		}
		else
		{
			die(7);
		}
		socket_write($c, $sndData);
		$getData = "";
		$getData = socket_read($c, 10000);
		if(empty($getData) !== true)
		{
			$lengthCode = ord($getData[1]) & 127;
			if($lengthCode < 0x7e)
			{
				$binLen = "";
				$mask = substr($getData, 2, 4);
				$msg  = substr($getData, 6);
				$dataLength = $lengthCode;
			}
			elseif($lengthCode == 0x7e)
			{
				$binLen = substr($getData, 2, 2);
				$mask   = substr($getData, 4, 4);
				$msg    = substr($getData, 8);
				list($dataLength) = array_values(unpack('n', $binLen));
			}
			elseif($lengthCode == 0x7f)
			{
				$binLen = substr($getData, 2, 4);
				$mask   = substr($getData, 8, 4);
				$msg    = substr($getData, 12);
				list($dataLength) = array_values(unpack('N', $binLen));
			}
			else
			{
				die(8);
			}
			$jj = 0;
			for ($ii = 0; $ii < strlen($msg); $ii++)
			{
				$unMasked = ($msg[$ii] ^ $mask[$jj]);
				$jj = (++$jj % 4);
			}
		}
		else
		{
			die(9);
		}
		socket_close($c);
	}
}
socket_close($socket);
