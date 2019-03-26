<?php
for ($i = 1; $i <= 100; $i++){
	echo md5("cmd.php".$i);
	echo "\r\n";
}