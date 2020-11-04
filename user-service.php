<?php
// Report all errors
error_reporting(E_ALL);
ini_set("display_errors", 1);

if(isset($_GET['method'])){
	
	$method = $_GET['method'];
	$service = new UserService();
	switch ($method) {
		case "forgotPw":
	        $service -> forgotPw();
			$response["status"] = $service->status;
	         
			echo json_encode($response);
	        break;
	        
	    case "resetPw":
	        $service -> resetPw();
	         
			echo json_encode($response);
	        break;

	    default:
	    	echo "Method not found: " . $method;

	}


}

class UserService{ 
	// email/user/password related services
	public $connection;
	public $emailFound;
	public $number_of_rows;
	public $email;
	public $row;
	public $status;

	function __construct()
	{
		//this api needs to be secured with an API key.
		//since I am the only one using this, I can hardcode it in

		if (session_status() == PHP_SESSION_NONE) {
		    session_start();
		}

		include '/var/www/html/db-connection.php';
		$this->connection = $conn;
		$this->status = "None.";
		$email = "";

		if(isset($_SESSION['email'])){
			$email = $_SESSION['email'];
		}

		if(isset($_GET['email'])){
			$email = $_GET['email'];
		}
		

		if(strlen($email)>0){
			$this->email = $email;
			$sql = "SELECT * FROM `users` WHERE email = ?"; 
			$result = $conn->prepare($sql); 
			$result->execute(array($email));
			$this->row = $result->fetch(PDO::FETCH_ASSOC);
			$this->number_of_rows = $result->rowCount();
		}

	}

	function forgotPw(){
		$email = $this->email;
		$row = $this->row;
		$number_of_rows = $this->number_of_rows;
		$conn = $this->connection;
		if($number_of_rows > 0){
			$this->emailFound = 1;
			$userid = $row['ID'];
			$this->userid = $userid;

			//create reset token
			$timestamp = time();
			$expire_date = time() + 24*60*60;
			$token_key = md5($timestamp.md5($email));
			$statement = $conn->prepare("INSERT INTO `passwordrecovery` (userid, token, expire_date) VALUES (:userid, :token, :expire_date)");
			$statement->bindParam(':userid', $userid);
			$statement->bindParam(':token', $token_key);
			$statement->bindParam(':expire_date', $expire_date);
			$statement->execute();

			//send email via amazon ses
			include 'send-email-service.php';	
			$SendEmailService = new SendEmailService();

			$reset_url = 'https://www.bjjtracker.com/reset-pw.php?token='.$token_key;
		    $subject = 'Reset your password.';
		    $body    = 'Click here to reset your password: <a href="'.$reset_url.'">'. $reset_url .'</a>';
		    $altBody = 'Click here to reset your password: ' . $reset_url;
		    $this->status = $SendEmailService -> sendEmail($subject, $body, $altBody, $email);


		}else{
			$this->emailFound = 0;
		}
	}

	function resetPw(){
		$conn = $this->connection;
		$token = $_GET['token'];
		$password = $_POST['password'];
		$passwordHash = password_hash($password, PASSWORD_DEFAULT);
		$statement = $conn->prepare("SELECT * FROM `passwordrecovery` where token = ?");
		$statement->execute(array($token));
		$row = $statement->fetch(PDO::FETCH_ASSOC);
		$userid = $row['userid'];

		$update_statement = $conn->prepare("UPDATE `users` SET password = ? where ID = ?");
		$update_statement->execute(array($passwordHash, $userid));

		$delete_statement = $conn->prepare("DELETE FROM `passwordrecovery` where token = ?");
		$delete_statement->execute(array($token));
	}



}

?>
