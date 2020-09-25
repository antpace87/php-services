<?php

function sendWelcomeEmail($email){
		include 'send-email-service.php';	
		$SendEmailService = new SendEmailService();

		$subject = 'Welcome to SplitWit A/B Testing';
	    $body    = "Thanks for registering with SplitWit A/B Testing.<br><br> Now's your chance to start running experiments and improve your website's conversion rate.<br /><br/>A good idea for your first experiment is to test the color of buttons. <a href='https://www.youtube.com/watch?v=G8sr8bpUfgA'>Watch this video to see how!</a><br /><br /> Reply back if you have any questions. We can help you get setup!<br><br><a href='https://www.splitwit.com/'><img src='https://www.splitwit.com/img/splitwit-logo.png'></a>";
	    $altBody = "Thanks for registering with SplitWit A/B Testing. Now's your chance to start experimenting and improving your website's conversion rate. A good idea for your first experiment is to test the color of buttons. Watch this video to see how: https://www.youtube.com/watch?v=G8sr8bpUfgA - Reply back if you have any questions. We can help you get setup!";
	    $SendEmailService -> sendEmail($subject, $body, $altBody, $email);


	}

sendWelcomeEmail("example@domain.com");

?>
