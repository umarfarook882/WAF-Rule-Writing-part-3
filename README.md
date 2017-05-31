# WAF Rule to prevent WordPress from 0-day Attack

  **(CVE-2017-8295) Wordpress 4.7.4 - Unauthorized Password Reset Vulnerability**
 
By default, WordPress is using an untrusted data to create a password reset link. That is supposed to be delivered only to the email address associated with the owner’s account.

If the From email header is not present WordPress will use the server one.

 *See wp-includes/pluggable.php*

      if ( !isset( $from_email ) ) { 
      // Get the site domain and get rid of www. 
      $sitename = strtolower( $_SERVER['SERVER_NAME'] ); 
      if ( substr( $sitename, 0, 4 ) == 'www.' ) { 
      $sitename = substr( $sitename, 4 );
      } 
      $from_email = 'wordpress@' . $sitename; 
      } 


**How the attack works?**

    1.The attacker makes their request to the “forgot password?” function.
    2.In the request, they set the “Host” http header to a domain they control. (let’s call it fos.org)
    3.The WordPress software generates an email with the secret link that will reset a user’s password. It looks up who it should send the email as (e.g.. the “From” field) by looking at the value in PHP of $_SERVER[‘SERVER_NAME’] which just so happens to be set by the “Host” http header field. Normally this would be your site’s domain, but in event of this attack the email “From” field will be wordpress@fos.org.   
    4.The email with secret key is queued for delivery to the WordPress user’s email address.
    5.Somehow (be it a bad email address, full inbox, or maybe even an away from office message that includes the original email) the email gets a response which includes the  original message and is delivered to the listed “From” field.
    6.The reply is delivered to the attacker’s inbox, they are then able to use the secret link and log in to the WordPress user’s account. 
 <br>
 
**How to prevent wordpress from 0-day exploits by WAF rule?**
    
    1.Analyse the vulnerability and draft a overview of the exploit process. 
    2.Find out which parameter or header is need  for this exploit to work. 

**Actual Request:**
      
      POST /waf-demo/wp-login.php?action=lostpassword HTTP/1.1
      Host: 127.0.0.1
      User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:53.0) Gecko/20100101 Firefox/53.0
      Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
      Accept-Language: en-US,en;q=0.5
      Accept-Encoding: gzip, deflate
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 76
      Referer: http://127.0.0.1/waf-demo/wp-login.php?action=lostpassword
      Cookie: wp-settings-time-1=1496252396; wordpress_test_cookie=WP+Cookie+check
      Connection: close
      Upgrade-Insecure-Requests: 1

      user_login=fos%40gmail.com&redirect_to=&wp-submit=Get+New+Password
  

**Edited Request (Attack Scenario)**
      
      POST /waf-demo/wp-login.php?action=lostpassword HTTP/1.1
      Host: fos.org
      User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:53.0) Gecko/20100101 Firefox/53.0
      Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
      Accept-Language: en-US,en;q=0.5
      Accept-Encoding: gzip, deflate
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 76
      Referer: http://127.0.0.1/waf-demo/wp-login.php?action=lostpassword
      Cookie: wp-settings-time-1=1496252396; wordpress_test_cookie=WP+Cookie+check
      Connection: close
      Upgrade-Insecure-Requests: 1

      user_login=fos%40gmail.com&redirect_to=&wp-submit=Get+New+Password 
<br>

    3.As in our case HOST Header is one where attacker try to change the Host for this exploit to work. 
    4.I have written a rule to check the Host Header, whenever the user requesting for resetting the  password for admin account.               So if host header value doesn't it match with actual host name. WAF will block it with status:403. 
    
**Demo Video**
  
   [![Alt text](https://img.youtube.com/vi/YFAHkS24EPY/0.jpg)](https://www.youtube.com/watch?v=YFAHkS24EPY)

      
