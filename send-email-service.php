<?php
// Report all errors
error_reporting(E_ALL);
ini_set("display_errors", 1);

//send email via amazon ses
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;


class SendEmailService{ 
	// send email services
	public $connection;
	public $status;
	public $email;
	 
	
	function __construct()
	{
		if (session_status() == PHP_SESSION_NONE) {
		    session_start();
		}

		include '/var/www/html/db-connection.php';
		$this->connection = $conn;
		$this->status = "None.";

	}

	function sendEmail($subject, $body, $altBody, $email){ 
		require '/var/www/html/PHPMailer/src/Exception.php';
		require '/var/www/html/PHPMailer/src/PHPMailer.php';
		require '/var/www/html/PHPMailer/src/SMTP.php';

		// Instantiation and passing `true` enables exceptions
		$mail = new PHPMailer(true);
		try {
		    //Server settings
		    $mail->SMTPDebug = 0;
		    $mail->isSMTP();                                            // Set mailer to use SMTP
		    $mail->Host       = 'email-smtp.XXX.amazonaws.com';  // Specify main and backup SMTP servers
		    $mail->SMTPAuth   = true;                                   // Enable SMTP authentication
		    $mail->Username   = 'XXX';                     // SMTP username
		    $mail->Password   = 'XXX';                               // SMTP password
		    $mail->SMTPSecure = 'tls';                                  // Enable TLS encryption, `ssl` also accepted
		    $mail->Port       = 587;                                    // TCP port to connect to

		    //Recipients
		    $mail->setFrom('info@XXX.com', 'Splitwit');
		    $mail->addAddress($email);     // Add a recipient
		    $mail->addReplyTo('info@XXX.com', 'Splitwit');

		    // Content
		    $mail->isHTML(true); // Set email format to HTML
		    
		    $mail->Subject = $subject;
		    $mail->Body    = $body;
		    $mail->AltBody = $altBody;

		    $mail->send();
		    $this->status = 'Message has been sent to: ' . $email;
		} catch (Exception $e) {
		    $this->status = "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
		}

		// echo $this->status;
		return $this->status;

	}

	



}

?>
