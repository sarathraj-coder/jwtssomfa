# Reference 


   # 1) Video reference , spring security 
   
   
      https://www.youtube.com/watch?v=NhY8q5B0s-s&list=PLD-mYtebG3X9HaZ1T39-aF4ghEtWy9-v3&index=17
      
      starts from video 8 
   
   
   # 2) mfa sample with TOTP, but the concept is fine to implement OTP 
   
   
        https://sultanov.dev/blog/multi-factor-authentication-with-spring-boot-and-oauth2/
        
        
   
   # 3) Jwt token generation (its already there)
   
   
        https://www.baeldung.com/spring-security-oauth-jwt

        keytool -genkeypair -alias jwt -keyalg RSA -keypass password -keystore testjwt.jks -storepass password

        keytool -importkeystore -srckeystore testjwt.jks  -destkeystore jwt.jks  -deststoretype pkcs12


        keytool -list -rfc --keystore jwt.jks | openssl x509 -inform pem -pubkey
        
        
   # 4) For Running 
    
            1)  change the database details in applicaiton.yml.
            
            2) rename the data.txt to data.sql in the first time. 
            
                
    
           
           
            