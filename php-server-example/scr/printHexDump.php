<?php

function printHexDump($inData)
{	
	for ($i = 0; $i < strlen($inData); $i++)
	{
		   printf("0x".dechex(ord($inData[$i]))." ");
		   if(($i % 8) == 7)
		   {
			printf("\n");
		   }
		}
	printf("\n");
}

