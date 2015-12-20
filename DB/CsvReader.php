<?php


include "QuerySQL.php"; // Includes the QuerySQL library




ServerConnect("127.0.0.1", "root", "", "File");  // DB Connection
$File = fopen("CsvFile.csv","r"); 
$I=0;
$Data;
global $Array;

while(!feof($File))   // Loop to read the csv file
  {
	  $Data = fgetcsv($File);
  if ($I>1){
  // echo '<br><br>SIZE '.sizeof($Data).'<br><br> ';
   for ($C=0; $C < sizeof($Data); $C++) {
            //echo $Data[$C] . ' -----> '.$C."<br />\n";
			$Array[$C]=$Data[$C];
			
        
		} 
		
		$Array[15]=substr($Array[0],0,8);
		$Array[15]=str_replace (":","-",$Array[15]);
		
			
		// InsertQuery into the DB
   InsertQuery("INSERT INTO Test (BSSID, FirstTimeSeen, LastTimeSeen, Channel, Speed, Privacy, Cipher, Authentication,Power, Beacons, IV, LanIP, ID_Length, Essid, EssidKey, Oui) VALUES ('$Array[0]','$Array[1]' ,'$Array[2]','$Array[3]','$Array[4]','$Array[5]','$Array[6]','$Array[7]','$Array[8]','$Array[9]','$Array[10]','$Array[11]','$Array[12]','$Array[13]','$Array[14]','$Array[15]')");	
  
 }
  $I++;
  }

fclose($File); // Closes the file




?>











