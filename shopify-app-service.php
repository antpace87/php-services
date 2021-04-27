<?php
namespace SplitWit\ShopifyService;
// Report all errors
error_reporting(E_ALL);
ini_set("display_errors", 1);

use Exception;

if(isset($_GET['method'])){
	
	$method = $_GET['method'];
	$service = new ShopifyService();

	switch ($method) {
		case "updateSnippetScriptTag":
			$service -> updateSnippetScriptTag();
	        break;
		case "uninstallApplication":
			$service -> uninstallApplication();
	        break;

		case "cancelSubscription":
			$service -> cancelSubscription();
	        break;

		case "createRecurringApplicationCharge":
			$service -> createRecurringApplicationCharge();
	        break;

		case "confirmSubscription":
			$service -> confirmSubscription();
	        break;

		case "customersRedact":
			$service -> gdprWebhook();
	        break;
		case "shopRedact":
			$service -> gdprWebhook();
	        break;
		case "customersData":
			$service -> gdprWebhook();
	        break;

	    default:
	    	echo "Method not found: " . $method;
	}
}

class ShopifyService{
	/**
     * @var string The API Key to use with these requests
     */
    private $api_key;

    /**
     * @var string The Secret Key associated with the provided API Key
     */
    private $secret;
    
    private $requestData;
    private $conn;

    public $splitwit_project_id;
    public $splitwit_account_id;

	public function __construct() {
		if (session_status() == PHP_SESSION_NONE) {
	        session_start();
	    }

		include '/db-connection.php';
		$this->conn = $conn; 
        $this->api_key = 'XXX';
        $this->secret = 'XXX';
     
        if(isset($_GET)){
        	$this->requestData = $_GET;
        }

        //every reqeust from Shopify will include an HMAC
        $hmac_valid = $this->verifyHmac($this->requestData);
		if(!$hmac_valid){
            // throw new Exception("HMAC not valid.");
            // #TODO: Show a marketing page instead. ie, redirect user to the shopify app directory listing
		}
	    
	}

	public function gdprWebhook(){
		header("HTTP/1.1 200 OK");
	}
	
	public function cancelSubscription(){
		
		$conn = $this->conn;
		$statement = $conn->prepare("SELECT * FROM `shopify_installation_complete` WHERE splitwit_account_id = :splitwit_account_id");
		$statement->execute(['splitwit_account_id' => $_SESSION['accountid']]);
		$row = $statement->fetch();
		$shop = $row['shop'];
		$access_token = $row['access_token'];

		$statement = $conn->prepare("SELECT * FROM `account` WHERE accountid = :accountid");
		$statement->execute(['accountid' => $_SESSION['accountid']]);
		$account_row = $statement->fetch();
		$charge_id = $account_row['billing_customer_id'];


		$delete_recurring_charge_url = "https://" . $this->api_key . ":" . $this->secret . "@" . $shop . "/admin/api/2020-04/recurring_application_charges/#" . $charge_id . ".json";

		$params = [];
    	$headers = array(
    		'X-Shopify-Access-Token: ' . $access_token,
		 	'content-type: application/json'
		);
		$json_string_params = json_encode($params);
		$delete = true;

		$delete_recurring_charge_curl_response_json = $this->curlApiUrl($delete_recurring_charge_url, $json_string_params, $headers, $delete);

		//delete shopify billing ID from db
		$empty_string = "";
		$sql = "UPDATE `account` SET payment_processor = ?, billing_customer_id = ? WHERE accountid = ?"; 
		$result = $conn->prepare($sql); 
		$result->execute(array($empty_string, $empty_string, $_SESSION['accountid']));
		
		echo $delete_recurring_charge_curl_response_json;


	}

	public function createRecurringApplicationCharge(){
		
		$conn = $this->conn;
		$statement = $conn->prepare("SELECT * FROM `shopify_installation_complete` WHERE splitwit_account_id = :splitwit_account_id");
		$statement->execute(['splitwit_account_id' => $_SESSION['accountid']]);
		$row = $statement->fetch();
		$shop = $row['shop'];
		$access_token = $row['access_token'];
		
		$create_recurring_charge_url = "https://" . $this->api_key . ":" . $this->secret . "@" . $shop . "/admin/api/2020-04/recurring_application_charges.json";
		$params = [
            'recurring_application_charge' => [
                'name' => 'Basic Plan',
                'price' => 25.0,
                // 'return_url' => "https://" . $shop . "/admin/apps/splitwit",
                // 'test' => true,
                'return_url' => "https://www.splitwit.com/service-layer/shopify-app-service?method=confirmSubscription"
            ]
    	];
    	$headers = array(
    		'X-Shopify-Access-Token: ' . $access_token,
		 	'content-type: application/json'
		);
		$json_string_params = json_encode($params);

		$create_recurring_charge_curl_response_json = $this->curlApiUrl($create_recurring_charge_url, $json_string_params, $headers);
		
		// var_dump($create_recurring_charge_curl_response_json);
		echo $create_recurring_charge_curl_response_json['recurring_application_charge']['confirmation_url'];
	}
	public function confirmSubscription(){
		
		$conn = $this->conn;
		$statement = $conn->prepare("SELECT * FROM `shopify_installation_complete` WHERE splitwit_account_id = :splitwit_account_id");
		$statement->execute(['splitwit_account_id' => $_SESSION['accountid']]);
		$row = $statement->fetch();
		$shop = $row['shop'];

		 
	 	$charge_id = $_REQUEST['charge_id'];
		//write shopify billing ID to db
		$sql = "UPDATE `account` SET payment_processor = ?, billing_customer_id = ?, current_period_end = ?, past_due = 0 WHERE accountid = ?"; 
		$result = $conn->prepare($sql); 
		$current_period_end = new \DateTime();  //we need the slash here (before DateTime class name), since we're in a different namespace (declared at the top of this file)
		$current_period_end->modify( '+32 day' );
		$current_period_end = $current_period_end->format('Y-m-d H:i:s'); 
		$payment_processor = "shopify";
		$result->execute(array($payment_processor, $charge_id, $current_period_end, $_SESSION['accountid']));
		
		//update current_period_end
		// var_dump($_REQUEST);
		//redirect to app
		header('Location: ' . "https://" . $shop . "/admin/apps/splitwit");

	}

	public function checkInstallationStatus(){
		$conn = $this->conn;
		$shop = $this->requestData['shop'];

		//check if app is already installed or not
		$statement = $conn->prepare("SELECT * FROM `shopify_installation_complete` WHERE shop = :shop");
		$statement->execute(['shop' => $shop]);
		$count = $statement->rowCount();
		if($count == 0){
			//app is not yet installed
			return false;
			
		}else{
			//app is already installed
			$row = $statement->fetch();
			return $row;
	
		}

	}
	
	public function verifyHmac($requestData){
		// verify HMAC signature. 
		// https://help.shopify.com/api/getting-started/authentication/oauth#verification
		if( !isset($requestData['hmac'])){
			return false;
		}

		$hmacSource = [];

		foreach ($requestData as $key => $value) {
		    
		    if ($key === 'hmac') { continue; }

		    // Replace the characters as specified by Shopify in the keys and values
		    $valuePatterns = [
		        '&' => '%26',
		        '%' => '%25',
		    ];
		    $keyPatterns = array_merge($valuePatterns, ['=' => '%3D']);
		    $key = str_replace(array_keys($keyPatterns), array_values($keyPatterns), $key);
		    $value = str_replace(array_keys($valuePatterns), array_values($valuePatterns), $value);

		    $hmacSource[] = $key . '=' . $value;
		}

		sort($hmacSource);
		$hmacBase = implode('&', $hmacSource);
		$hmacString = hash_hmac('sha256', $hmacBase, $this->secret);
		// Verify that the signatures match
        if ($hmacString !== $requestData['hmac']) {
            return false;
        }else{
        	return true;
        }
	}

	public function curlApiUrl($url, $params, $headers = false, $use_post = true, $use_delete = false, $use_put = false){
		
		// echo "<br />URL: ".$url." <br />";

		$curl_connection = curl_init();
		// curl_setopt($curl_connection, CURLOPT_FOLLOWLOCATION, true);
		if($headers){
			curl_setopt($curl_connection, CURLOPT_HTTPHEADER, $headers);
			curl_setopt($curl_connection, CURLOPT_HEADER, false);
		}
		curl_setopt($curl_connection, CURLOPT_URL, $url);
	    
	    // TODO: refactor these three conditions into one, that accepts the RESTful request type!!
	    if($use_post){
		    curl_setopt($curl_connection, CURLOPT_POST, true);
			curl_setopt($curl_connection, CURLOPT_POSTFIELDS, $params);
		}
	    if($use_delete){
		    curl_setopt($curl_connection, CURLOPT_CUSTOMREQUEST, "DELETE");
		}
	    if($use_put){
		    curl_setopt($curl_connection, CURLOPT_CUSTOMREQUEST, "PUT");
			curl_setopt($curl_connection, CURLOPT_POSTFIELDS, $params);
		}
		//end TODO

		curl_setopt($curl_connection, CURLOPT_RETURNTRANSFER, true);
		$curl_response = curl_exec($curl_connection);
		$curl_response_json = json_decode($curl_response,true);
		curl_close($curl_connection);
		return $curl_response_json;
	}
	
	public function verifyWebhook($data, $hmac_header){
	  $calculated_hmac = base64_encode(hash_hmac('sha256', $data, $this->secret, true));
	  return hash_equals($hmac_header, $calculated_hmac);
	}

	public function uninstallApplication(){
		$conn = $this->conn; 
		
		$res = '';
		$hmac_header = $_SERVER['HTTP_X_SHOPIFY_HMAC_SHA256'];
		$topic_header = $_SERVER['HTTP_X_SHOPIFY_TOPIC'];
		$shop_header = $_SERVER['HTTP_X_SHOPIFY_SHOP_DOMAIN'];
		$data = file_get_contents('php://input'); //similar to $_POST
		$decoded_data = json_decode($data, true);
		$verified = $this->verifyWebhook($data, $hmac_header);

		if( $verified == true ) {
		  if( $topic_header == 'app/uninstalled' || $topic_header == 'shop/update') {
		    if( $topic_header == 'app/uninstalled' ) {
				$domain = $decoded_data['domain'];

				// $domain = "splitwit.myshopify.com";

				// $stmt = $conn->prepare("CALL uninstall_shopify_app(?)");
				// $stmt->bindParam(1, $domain, PDO::PARAM_STR|PDO::PARAM_INPUT_OUTPUT, 4000); 
				// $stmt->execute();

				$statement1 = $conn->prepare("SELECT * FROM `shopify_installation_complete` WHERE shop = ?");
				$statement1->execute(array($domain));
				$row = $statement1->fetch();
				$accountid = $row['splitwit_account_id'];

				//delete shopify billing ID from db
				$empty_string = "";
				$result = $conn->prepare("UPDATE `account` SET payment_processor = ?, billing_customer_id = ? WHERE accountid = ?"); 
				$result->execute(array($empty_string, $empty_string, $accountid));

				$statement = $conn->prepare("DELETE FROM `shopify_installation_complete` WHERE shop = ?");
				$statement->execute(array($domain));



		    } else {
		      $res = $data;
		    }
		  }
		} else {
		  $res = 'The request is not from Shopify';
		}

	}

	public function updateSnippetScriptTag(){
		$projectid = $_GET['projectid'];
		$conn = $this->conn;
		$sql = "SELECT * FROM `shopify_installation_complete` WHERE splitwit_project_id = ?"; 
		$result = $conn->prepare($sql); 
		$result->execute(array($projectid));
		$row = $result->fetch(\PDO::FETCH_ASSOC);
		$number_of_rows = $result->rowCount();
		if($number_of_rows == 1){
			$access_token = $row['access_token'];
			$shop = $row['shop'];
			$sql = "SELECT * FROM `project` WHERE projectid = ?"; 
			$project_result = $conn->prepare($sql); 
			$project_result->execute(array($projectid));
			$project_row = $project_result->fetch(\PDO::FETCH_ASSOC);
			$snippet = $project_row['snippet'];			

			$script_tag_url = "https://" . $this->api_key . ":" . $this->secret . "@" . $shop . "/admin/api/2020-04/script_tags.json";
        	$headers = array(
			  'X-Shopify-Access-Token:' . $access_token,
			  'content-type: application/json'
			);
        	$params = [];
        	$json_string_params = json_encode($params);
        	$use_post = false;
			//get existing script tag
			$get_script_curl_response_json = $this->curlApiUrl($script_tag_url, $json_string_params, $headers, $use_post);
			$tags = $get_script_curl_response_json['script_tags'];
		
			foreach ($tags as $tag) {
				$id = $tag['id'];
				$delete_script_tag_url = "https://" . $this->api_key . ":" . $this->secret . "@" . $shop . "/admin/api/2020-04/script_tags/" . $id . ".json";
				$use_delete = true;
				$delete_script_curl_response_json = $this->curlApiUrl($delete_script_tag_url, $json_string_params, $headers, $use_post, $use_delete);
			}
			 
			//add snippet
			$snippet = "https://www.splitwit.com/snippet/" . $snippet . "?t=" . time();
			$params = [
                'script_tag' => [
                    'event' => 'onload',
                    'src' => $snippet 
                ]
        	];
			$json_string_params = json_encode($params);
			$create_script_curl_response_json = $this->curlApiUrl($script_tag_url, $json_string_params, $headers);
			// var_dump($create_script_curl_response_json);
			// echo "snip: " . $snippet;			 

		}
	}

	public function makeSureRecordsExist($already_installed){

		$conn = $this->conn; 
		// $already_installed = $this->checkInstallationStatus();
		//get this from DB after above curl is done!
		$access_token = $already_installed['access_token'];

		$shop = $already_installed['shop'];
		$store_name = explode(".", $shop);
		$store_name = ucfirst($store_name[0]);
		
		$statement = $conn->prepare("SELECT * FROM `account` WHERE email = :email");
		$statement->execute(['email' => $already_installed['associated_user_email']]);
		$count = $statement->rowCount();
		if($count == 0){
            //create account
			$method = "thirdPartyAuth";
			

			$user_service_url = "https://www.splitwit.com/service-layer/user-service.php?third_party_source=shopify&method=" . $method . "&email=".$already_installed['associated_user_email']."&companyname=" . $store_name . "&first=" . $already_installed['associated_user_first_name'] . "&last=" . $already_installed['associated_user_last_name'];
			
			$params = [];

			$curl_user_response_json = $this->curlApiUrl($user_service_url, $params);
			$account_id = $curl_user_response_json['userid']; 
			
			//and set against installation record
			$statement = $conn->prepare("UPDATE `shopify_installation_complete` SET splitwit_account_id = ? WHERE shopify_installation_complete_id = ?");

			$statement->execute(array($account_id, $already_installed['shopify_installation_complete_id']));

				
		}else{
			//get account ID 
			$row = $statement->fetch(\PDO::FETCH_ASSOC);
			$account_id = $row['accountid'];
		}

		//look up project that has this account ID 
		$statement = $conn->prepare("SELECT * FROM `project` WHERE accountid = :accountid");
		$statement->execute(['accountid' => $account_id]);
		$count = $statement->rowCount();
		
		if($count == 0){
			$method = "createProject";
			$project_service_url = "https://www.splitwit.com/service-layer/project-service.php?method=" . $method . "&accountid=" . $account_id;

			$params = [
	            'projectname'    => $store_name . " Shopify",
	            'projectdomain'    => "https://".$shop,
	            'projectdescription'    => ""
	        ];

			$curl_project_response_json = $this->curlApiUrl($project_service_url, $params);
			$project_id = $curl_project_response_json['projectid'];
			$snippet = $curl_project_response_json['snippet'];

			//add snippet, but delete older, existing snippets first!
			$script_tag_url = "https://" . $this->api_key . ":" . $this->secret . "@" . $shop . "/admin/api/2020-04/script_tags.json";
			
        	$headers = array(
			  'X-Shopify-Access-Token:' . $access_token,
			  'content-type: application/json'
			);
        	$params = [];
        	$json_string_params = json_encode($params);
        	$use_post = false;
			//get any existing script tags that we added on previous installations
			$get_script_curl_response_json = $this->curlApiUrl($script_tag_url, $json_string_params, $headers, $use_post);
			// var_dump($get_script_curl_response_json);
			$tags = $get_script_curl_response_json['script_tags'];
			//delete existing tags
			foreach ($tags as $tag) {
				$id = $tag['id'];
				
				$delete_script_tag_url = "https://" . $this->api_key . ":" . $this->secret . "@" . $shop . "/admin/api/2020-04/script_tags/" . $id . ".json";
				$use_delete = true;
				$delete_script_curl_response_json = $this->curlApiUrl($delete_script_tag_url, $json_string_params, $headers, $use_post, $use_delete);
			}

        	//add snippet
			$params = [
                'script_tag' => [
                    'event' => 'onload',
                    'src' => 'https://www.splitwit.com/snippet/' . $snippet
                ]
        	];
			$json_string_params = json_encode($params);
			$create_script_curl_response_json = $this->curlApiUrl($script_tag_url, $json_string_params, $headers);

			//set against installation record
			$statement = $conn->prepare("UPDATE `shopify_installation_complete` SET splitwit_project_id = ? WHERE shopify_installation_complete_id = ?");
			$statement->execute(array($project_id, $already_installed['shopify_installation_complete_id']));

		}else{
			//get projectid from lookup
			$row = $statement->fetch(\PDO::FETCH_ASSOC);
			$project_id = $row['projectid'];
		}
		//i need to return a project ID and an account ID
		$this->splitwit_project_id = $project_id;
		$this->splitwit_account_id = $account_id;
		
	}
	public function buildAuthorizationUrl($reauth = false){
		$conn = $this->conn;
		$requestData = $this->requestData;
		$scopes = "write_script_tags"; //write_orders,read_customers, read_content
		$nonce = bin2hex(random_bytes(10));
		$shop = $requestData['shop'];

		//first check if there is already a record for this shop. If there is, delete it first.
		$statement = $conn->prepare("SELECT * FROM `shopify_authorization_redirect` WHERE shop = :shop");
		$statement->execute(['shop' => $shop]);
		$count = $statement->rowCount();
		
		if($count > 0){
			$statement = $conn->prepare("DELETE FROM `shopify_authorization_redirect` WHERE shop = :shop");
			$statement->execute(['shop' => $shop]);
		}

		$statement = $conn->prepare("INSERT INTO `shopify_authorization_redirect` (shop, nonce, scopes) VALUES (:shop, :nonce, :scopes)");
		$statement->bindParam(':shop', $shop);
		$statement->bindParam(':nonce', $nonce);
		$statement->bindParam(':scopes', $scopes);
		$statement->execute();

		
		$redirect_uri = "https://www.splitwit.com/shopify-app/authorize-application";
		
		if($reauth){ //change the redirect URI
			$redirect_uri = "https://www.splitwit.com/shopify-app/reauthorize-application";
		}

		$redirect_url = "https://".$shop."/admin/oauth/authorize?client_id=". $this->api_key ."&scope=".$scopes."&redirect_uri=". $redirect_uri ."&state=".$nonce . "&grant_options[]=per-user";


		//."&grant_options[]=per-user";
		// grant_options[]=per-user is needed to get associated user email address
		//but grant_options[]=per-user gives an online token that will expire.
		return $redirect_url;

	}

	public function reAuthenticate(){
		$conn = $this->conn; 
		$requestData = $this->requestData;
		$requiredKeys = ['code', 'hmac', 'state', 'shop'];
        foreach ($requiredKeys as $required) {
            if (!in_array($required, array_keys($requestData))) {
                throw new Exception("The provided request data is missing one of the following keys: " . implode(', ', $requiredKeys));
                // return;
            }
        }

        //lookup and validate nonce
		$shop = $requestData['shop'];
		
		$statement = $conn->prepare("SELECT * FROM `shopify_authorization_redirect` WHERE shop = :shop");
		$statement->execute(['shop' => $shop]);
		$count = $statement->rowCount();
		if($count == 0){
            throw new Exception("Nonce not found for this shop.");
		}
		$row = $statement->fetch();
		$nonce = $row['nonce'];
		//
		
		//make sure the 'state' parameter provided matches the stored nonce
		$state = $requestData['state'];
		if($state !== $nonce){
            throw new Exception("Nonce does not match provided state.");
		}
		//
		
		//validate the shop name
		$pattern = "/[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com[\/]?/";
		if(!preg_match($pattern, $shop)) {
            throw new Exception("The shop name is an invalid Shopify hostname.");
		}

		//exchange the access code for an access token by sending a request to the shop’s access_token endpoint
		$code = $requestData['code'];
		$post_url = "https://" . $shop . "/admin/oauth/access_token";
		
		$params = [
            'client_id'    => $this->api_key,
            'client_secret'    => $this->secret,
            'code'    => $code
        ];

        $curl_response_json = $this->curlApiUrl($post_url, $params);
        $access_token = $curl_response_json['access_token'];
        
        $statement = $conn->prepare("UPDATE `shopify_installation_complete` SET access_token = ? WHERE shop = ?");
		$statement->execute(array($access_token, $shop));

		header('Location: ' . "https://www.splitwit.com/shopify-app/home?shop=".$shop);
	}

	public function authorizeApplication(){
		$conn = $this->conn; 
		$requestData = $this->requestData;
		$requiredKeys = ['code', 'hmac', 'state', 'shop'];
        foreach ($requiredKeys as $required) {
            if (!in_array($required, array_keys($requestData))) {
                throw new Exception("The provided request data is missing one of the following keys: " . implode(', ', $requiredKeys));
                // return;
            }
        }

		//lookup and validate nonce
		$shop = $requestData['shop'];
		
		$statement = $conn->prepare("SELECT * FROM `shopify_authorization_redirect` WHERE shop = :shop");
		$statement->execute(['shop' => $shop]);
		$count = $statement->rowCount();
		if($count == 0){
            throw new Exception("Nonce not found for this shop.");
		}
		$row = $statement->fetch();
		$nonce = $row['nonce'];
		//
		
		//make sure the 'state' parameter provided matches the stored nonce
		$state = $requestData['state'];
		if($state !== $nonce){
            throw new Exception("Nonce does not match provided state.");
		}
		//
		
		//validate the shop name
		$pattern = "/[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com[\/]?/";
		if(!preg_match($pattern, $shop)) {
            throw new Exception("The shop name is an invalid Shopify hostname.");
		}
		//

		$already_installed = $this->checkInstallationStatus();
		//if it is already installed, then lets update the access token 
        if(!$already_installed){
        	//install the app
        	
			//exchange the access code for an access token by sending a request to the shop’s access_token endpoint
			$code = $requestData['code'];
			$post_url = "https://" . $shop . "/admin/oauth/access_token";
			
			$params = [
	            'client_id'    => $this->api_key,
	            'client_secret'    => $this->secret,
	            'code'    => $code
	        ];

	        $curl_response_json = $this->curlApiUrl($post_url, $params);
			$access_token = $curl_response_json['access_token'];
			// var_dump($curl_response_json);
			// die();
			//record this installation
	        $statement = $conn->prepare("INSERT INTO `shopify_installation_complete` (shop, access_token, scope, expires_in, associated_user_scope, associated_user_id, associated_user_first_name, associated_user_last_name, associated_user_email, associated_user_email_verified, associated_user_account_owner, associated_user_account_locale, associated_user_account_collaborator) VALUES (:shop, :access_token, :scope, :expires_in, :associated_user_scope, :associated_user_id, :associated_user_first_name, :associated_user_last_name, :associated_user_email, :associated_user_email_verified, :associated_user_account_owner, :associated_user_account_locale, :associated_user_account_collaborator)");
			
			$statement->bindParam(':shop', $shop);
			
			$statement->bindParam(':access_token', $access_token);
			$statement->bindParam(':scope', $curl_response_json['scope']);
			$statement->bindParam(':expires_in', $curl_response_json['expires_in']);
			$statement->bindParam(':associated_user_scope', $curl_response_json['associated_user_scope']);
			$statement->bindParam(':associated_user_id', $curl_response_json['associated_user']['id']);
			$statement->bindParam(':associated_user_first_name', $curl_response_json['associated_user']['first_name']);
			$statement->bindParam(':associated_user_last_name', $curl_response_json['associated_user']['last_name']);
			$statement->bindParam(':associated_user_email', $curl_response_json['associated_user']['email']);
			$statement->bindParam(':associated_user_email_verified', $curl_response_json['associated_user']['email_verified']);
			$statement->bindParam(':associated_user_account_owner', $curl_response_json['associated_user']['account_owner']);
			$statement->bindParam(':associated_user_account_locale', $curl_response_json['associated_user']['locale']);
			$statement->bindParam(':associated_user_account_collaborator', $curl_response_json['associated_user']['collaborator']);

			$statement->execute();
			$installation_complete_id = $conn->lastInsertId();
			 
			if(isset($curl_response_json['associated_user']['email']) && strlen($curl_response_json['associated_user']['email']) > 0){

				$store_name = explode(".", $shop);
				$store_name = ucfirst($store_name[0]);

				//create account
				$method = "thirdPartyAuth";
				$user_service_url = "https://www.splitwit.com/service-layer/user-service.php?third_party_source=shopify&method=" . $method . "&email=".$curl_response_json['associated_user']['email']."&companyname=" .$store_name . "&first=" . $curl_response_json['associated_user']['first_name'] . "&last=" . $curl_response_json['associated_user']['last_name'] ;
				
				$params = [];

				$curl_user_response_json = $this->curlApiUrl($user_service_url, $params);
				// $new_account = $curl_user_response_json['newAccount'];
				$account_id = $curl_user_response_json['userid']; 
				
				$method = "createProject";
				
				$project_service_url = "https://www.splitwit.com/service-layer/project-service.php?method=" . $method . "&accountid=" . $account_id;

				$params = [
		            'projectname'    => $store_name . " Shopify",
		            'projectdomain'    => "https://".$shop,
		            'projectdescription'    => ""
		        ];

				$curl_project_response_json = $this->curlApiUrl($project_service_url, $params);
				$project_id = $curl_project_response_json['projectid'];
				$snippet = $curl_project_response_json['snippet'];
				
				//create their first experiment
				// $method = "createExperiment";
				
				// $experiment_service_url = "https://www.splitwit.com/service-layer/project-service.php?method=" . $method . "&accountid=" . $account_id . "&projectid=" . $project_id;

				// $params = [
		  //           'experimentname'    => "My First A/B Test",
		  //           'experimentdescription'    => "",
		  //           'editorurl'    => "https://".$shop
		  //       ];

				// $curl_experiment_response_json = $this->curlApiUrl($experiment_service_url, $params);
				// $experiment_id = $curl_experiment_response_json['experimentid'];

				//create condition record for that experiment
				
				// $method = "addExperimentCondition";
				
				// $condition_service_url = "https://www.splitwit.com/service-layer/project-service.php?method=" . $method . "&experimentid=" . $experiment_id . "&conditiontype=target";

				// $params = [
		  //           'matchtype'    => "substring",
		  //           'url'    => "https://".$shop
		  //       ];

				// $curl_condition_service_url_response_json = $this->curlApiUrl($condition_service_url, $params);


				//inject JS snippet into site
				// https://shopify.dev/docs/admin-api/rest/reference/online-store/scripttag#create-2020-04
				$create_script_tag_url = "https://" . $this->api_key . ":" . $this->secret . "@" . $shop . "/admin/api/2020-04/script_tags.json";
				$params = [
	                'script_tag' => [
	                    'event' => 'onload',
	                    'src' => 'https://www.splitwit.com/snippet/' . $snippet
	                ]
	        	];

	        	$headers = array(
				  'X-Shopify-Access-Token:' . $access_token,
				  'content-type: application/json'
				);

				$json_string_params = json_encode($params);

				$create_script_curl_response_json = $this->curlApiUrl($create_script_tag_url, $json_string_params, $headers);
				// var_dump($create_script_curl_response_json);
				
				//shopify app should only ever have access to this one project.
				//write accountID and ProjectID to this shopify_installation_complete record.

				$statement = $conn->prepare("UPDATE `shopify_installation_complete` SET splitwit_account_id = ?, splitwit_project_id = ? WHERE shopify_installation_complete_id = ?");

				$statement->execute(array($account_id, $project_id, $installation_complete_id));
				
	    	}
			
	    	//create webhook to listen for when app in uninstalled.
			//https://{username}:{password}@{shop}.myshopify.com/admin/api/{api-version}/{resource}.json
			// https://shopify.dev/docs/admin-api/rest/reference/events/webhook#create-2020-04
			$create_webhook_url = "https://" . $this->api_key . ":" . $this->secret . "@" . $shop . "/admin/api/2020-04/webhooks.json";
			$params = [
	                'webhook' => [
	                    'topic' => 'app/uninstalled',
	                    'address' => 'https://www.splitwit.com/service-layer/shopify-app-service?method=uninstallApplication',
	                    'format' => 'json'
	                ]
	        ];

			$headers = array(
			  'X-Shopify-Access-Token:' . $access_token,
			  'content-type: application/json'
			);
			
			$json_string_params = json_encode($params);
	
	    	$create_webhook_curl_response_json = $this->curlApiUrl($create_webhook_url, $json_string_params, $headers);
			
			
    		//installation complete.
    	}

    	header('Location: ' . "https://" . $shop . "/admin/apps/splitwit");
		
	}

}


?>
