package com.business.busi.configuration;



import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.business.busi.exception.MyBusinessProException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@Component
public class JwtService {
	
	 private static final Logger logger = LoggerFactory.getLogger(JwtService.class); 

	@Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;
	
//	 private final String SECRET_KEY = "0123456789012345678901234567890101234567890123456789012345678901";
//    
//     private final long EXPIRATION_TIME = 864_000_00L;

    
    @Autowired
    private StringRedisTemplate redisTemplate;
    
    
	    public String generateToken(String username){
	    	String token = null;
	    	try {
	        Map<String, Object> claims = new HashMap<>();
	        token = createToken(claims, username);
	    	}catch(Exception e) {
	    		logger.error("Exception generateToken failed: {}", username, e);
	            throw new MyBusinessProException("Exception error generateToken ", e.getMessage());
	    	}
			return token;
	    }
    

	    private  String createToken(Map<String, Object> claims, String username){
	    	String token = null;
	    	try {
	                token = Jwts.builder()
	                .setClaims(claims)
	                .setSubject(username)
	                .setIssuedAt(new Date())
	                .setExpiration(new Date(System.currentTimeMillis() + expiration))
	                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
	                .compact();
	        
	        String hashedToken = hashToken(token);
		    redisTemplate.opsForValue().set(hashedToken, username, expiration, TimeUnit.MILLISECONDS);	
	    	}catch(NoSuchAlgorithmException e) {
	    		logger.error("NoSuchAlgorithmException createToken failed: {}", username, e);
	            throw new MyBusinessProException("NoSuchAlgorithmException error createToken ", e.getMessage());
	    	}catch(Exception e) {
	    		logger.error("Exception createToken failed: {}", username, e);
	            throw new MyBusinessProException("Exception error createToken ", e.getMessage());
	    	}
	        return token;
	    }
	    
	    public String hashToken(String token) throws NoSuchAlgorithmException {
	        MessageDigest digest = MessageDigest.getInstance("SHA-256");
	        byte[] hashBytes = digest.digest(token.getBytes());
	        return Base64.getEncoder().encodeToString(hashBytes);
	    }
	    
	    
	    private Key getSigningKey() {
	    byte [] Keybytes = Decoders.BASE64.decode(secret);
	    return Keys.hmacShaKeyFor(Keybytes);
	    }

	    
	    public  String extractUsername(String token) {
	        return extractClaim(token, Claims::getSubject);
	    }
	    
	    public Date extractExpiration(String token) {
	    	return extractClaim(token,Claims::getExpiration);
	    }

	    
	    public  <T> T extractClaim(String token, Function<Claims,T> claimsResolver) {
	       final Claims claims = extractAllClaims(token);
	       return claimsResolver.apply(claims);
	    }
	    
	    private Claims extractAllClaims(String token) {
	    	return Jwts
	    			.parserBuilder()
	    			.setSigningKey(getSigningKey())
	    			.build()
	    			.parseClaimsJws(token)
	    			.getBody();
	    }
	  
	    
	    public boolean validateToken(String token, UserDetails userDetails) throws NoSuchAlgorithmException{
	        try {
	            String username = extractUsername(token);

	            if (!username.equals(userDetails.getUsername())) {
	                return false;
	            }

	            if (isTokenExpired(token)) {
	                return false;
	            }

	            String hashedToken = hashToken(token);
	            return redisTemplate.hasKey(hashedToken);

	        } catch (JwtException  e) {
	          logger.error("JwtException validateToken failed: {}", e.getMessage(), e);
	          throw new MyBusinessProException("JwtException error validateToken ", e.getMessage());
	        } catch (NoSuchAlgorithmException e) {
	          logger.error("NoSuchAlgorithmException validateToken failed: {}", e.getMessage(), e);
		      throw new MyBusinessProException("NoSuchAlgorithmException error validateToken ", e.getMessage());
			}catch (Exception  e) {
		      logger.error("Exception validateToken failed: {}", e.getMessage(), e);
		      throw new MyBusinessProException("Exception error validateToken ", e.getMessage());
		    }
	    }
	    


	    private  boolean isTokenExpired(String token) {
	        return extractClaim(token, Claims::getExpiration).before(new Date());
	    }
	    
	    public boolean isTokenValid(String token){
	    	boolean isValid = false;
	    	try {
	    	String hashedToken = hashToken(token);
	        isValid =  redisTemplate.hasKey(hashedToken);
	    	}catch(NoSuchAlgorithmException e) {
	    		logger.error("NoSuchAlgorithmException isTokenValid failed: {}", e.getMessage(), e);
			    throw new MyBusinessProException("NoSuchAlgorithmException error isTokenValid ", e.getMessage());	
	    	}catch(Exception e) {
	    		logger.error("Exception isTokenValid failed: {}", e.getMessage(), e);
			    throw new MyBusinessProException("Exception error isTokenValid ", e.getMessage());	
	    	}
			return isValid;
	    }
	    
	    public void deleteToken(String token){
	    	try {
	    	String hashedToken = hashToken(token);
	        redisTemplate.delete(hashedToken);
	    	}catch(NoSuchAlgorithmException e) {
	    		logger.error("NoSuchAlgorithmException deleteToken failed: {}", e.getMessage(), e);
			    throw new MyBusinessProException("NoSuchAlgorithmException error deleteToken ", e.getMessage());
	    	}catch(Exception e) {
	    		logger.error("Exception deleteToken failed: {}", e.getMessage(), e);
			    throw new MyBusinessProException("Exception error deleteToken ", e.getMessage());
	    	}
	    }

    
	
}


