<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Encrypt your text!</title>
</head>
<body>
	<form action="/action_page.php">
		User Text:<br> <input type="text" name="userText"
			value="" id="userText"> <br> <input onClick="encryptText()"
			type="button" value="Submit">
	</form>
	<p id="encryptedText"></p><p id="decryptedText"></p>
</body>
<script src="js/crypto4js.min.js"></script>
<script src="https://code.jquery.com/jquery-3.2.1.min.js"></script>
<script>
	var mod = "917ea743d62a559b60e3b1c4eebc07bbf8431e03a31d654efb202883b70f2c5d55aa0fc895527f1980b15704585ab995edca0b9fa13e3095b9d5eb3893d98368f2164b1f7284d35c28b35c45ebdca5460c9322a6e1678d77b7759a59ee348b34cd04c5d218c8d64e614f4f9a4e144c67077bbbdc9b298033f3613a8c7d394bbd";
	var exp = "10001";
	function encryptText() {
		var userInput = document.getElementById("userText").value;
		if(userInput == ""){
			
			alert("please enter a value");
			return;
		}
		if(mod == "" || exp == ""){
			alert("internal server error");
			return;
		}
		var originalLength = userInput.length;
		var crypt=new Crypto();
		var base64EncryptedText = crypt.RSAEncrypt(mod,exp,userInput);
		document.getElementById("encryptedText").innerHTML ="encrypted: "+ base64EncryptedText ;
		
		$.ajax({

			url : "http://localhost:8080/RSAEncryption/DecryptText",
			jsonpCallback : 'modexp',
			dataType : 'jsonp',
			type : "POST",
			data : {
			"ValLength": originalLength,
			"userText": base64EncryptedText
			},
			success : function(response) {
				console.log(response);
			document.getElementById("decryptedText").innerHTML = "decrpyted: "+ response.decryptedText ;
			}
		});

	}
</script>
</html>
