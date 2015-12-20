<?php

$Connect;

//  DataBase Connections
function ServerConnect($Server, $User, $Password, $DB) {

	global $Connect;
	$Connect = mysqli_connect($Server, $User, $Password, $DB);
	
	 /*if ($Connect)
	echo " \n Succssefully connected to DB";
	 else if (!$Connect)
	 echo " \n Die ";
    */
}

// SELECT
function SelectQuery($Query) {

	global $Count, $Connect;
	$Count = 0;
	$Matrix = NULL;
    if ($Return = mysqli_query($Connect, $Query)) {
		// Fetch one and one row
		while ($Value = mysqli_fetch_row($Return)) {

			// Gets the current row
			for ($i = 0; $i < mysqli_num_fields($Return); $i++) {
				// select the current field
				$Array[$i] = $Value[$i];

			}
			$Matrix[$Count] = $Array;
			// Current row
			$Count++;

		}
		// Free result set
		mysqli_free_result($Return);

	}
	// Returns the selected table

	if ($Count == 0)

		return 0;
	else
		return $Matrix;
		
		

}

// INSERT
function InsertQuery($Query) {
	global $Connect;
	if ($Connect -> query($Query) === TRUE) {
		//echo "New record successfully added";
		return TRUE;
	} else {
		//echo "Error: " . $Query . "<br>" . $Connect -> error;
		return FALSE;
	}
}

// UPDATE
function UpdateQuery($Query) {

	global $Connect;
	if ($Connect -> query($Query) === TRUE) {
		//echo "Record updated successfully";
		//return TRUE;

	} else {
		//echo "Error updating record: " . $Connect -> error;
		//return FALSE;
	}

}

// Delete
function DeleteQuery($Query) {

	global $Connect;

	if ($Connect -> query($Query) === TRUE) {
		//echo "Record successfully deleted ";
		//return TRUE;
	} else {
		//echo "Error deleting record: " . $Connect -> error;
		//return FALSE;

	}

}

function ReturnConnection(){
	global $Connect;
	return  $Connect;
}

// Closes the connection with the DB
function CloseConnection() {
	global $Connect;
	mysqli_close($Connect);
	
	
}
?>
