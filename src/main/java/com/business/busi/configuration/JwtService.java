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
    
    @Value("${jwt.refresh}")
    private long refreshExpiration;
	
//	 private final String SECRET_KEY = "0123456789012345678901234567890101234567890123456789012345678901";
//    
//     private final long EXPIRATION_TIME = 864_000_00L;

    
    @Autowired
    private StringRedisTemplate redisTemplate;
    
    
       public String generateAccessToken(String username) {
            return generateToken(username, expiration);
        }

    
       public String generateRefreshToken(String username) {
            return generateToken(username, refreshExpiration);
        }
    
    
	    public String generateToken(String username,long expirationTime){
	    	String token = null;
	    	try {
	        Map<String, Object> claims = new HashMap<>();
	        token = createToken(claims, username, expirationTime);
	    	}catch(Exception e) {
	    		logger.error("Exception generateToken failed: {}", username, e);
	            throw new MyBusinessProException("Exception error generateToken ", e.getMessage());
	    	}
			return token;
	    }
    

	    private String createToken(Map<String, Object> claims, String username, long expirationTime){
	    	String token = null;
	    	try {
	                token = Jwts.builder()
	                .setClaims(claims)
	                .setSubject(username)
	                .setIssuedAt(new Date())
	                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
	                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
	                .compact();
	        
	        String hashedToken = hashToken(token);
		    redisTemplate.opsForValue().set(hashedToken, username, expirationTime, TimeUnit.MILLISECONDS);	
	    	}catch(NoSuchAlgorithmException e) {
	    		logger.error("NoSuchAlgorithmException createToken failed: {}", username, e);
	            throw new MyBusinessProException("NoSuchAlgorithmException error createToken ", e.getMessage());
	    	}catch(Exception e) {
	    		logger.error("Exception createToken failed: {}", username, e);
	            throw new MyBusinessProException("Exception error createToken ", e.getMessage());
	    	}
	        return token;
	    }
	    
	    public Map<String, String> refreshToken(String oldToken) {
	        Map<String, String> refreshData = new HashMap<String, String>();
	        try {
	            
	            if (!isTokenValid(oldToken)) {
	                throw new MyBusinessProException("Invalid or expired token.");
	            }

	           
	            String username = extractUsername(oldToken);

	            
	            String hashedToken = hashToken(oldToken);

	           
	            if (redisTemplate.opsForValue().get(hashedToken) == null) {
	                throw new MyBusinessProException("Token not found in Redis.");
	            }

	          
	            String newToken = generateAccessToken(username);

	            
	            String hashedNewToken = hashToken(newToken);
	            redisTemplate.opsForValue().set(hashedNewToken, username, expiration, TimeUnit.MILLISECONDS);
	        
	            
	            redisTemplate.delete(hashedToken);
	  
	         
	            refreshData.put("refreshedToken", newToken);
	            return refreshData;

	        } catch (Exception e) {
	            logger.error("Exception in refreshToken failed: {}", oldToken, e);
	            throw new MyBusinessProException("Exception error in refreshToken", e.getMessage());
	        }
	    }
	    

//	    public Map<String,String> refreshToken(String oldToken) {
//	    	Map<String,String> refreshData = new HashMap<String,String>();
//	        try {
//	            if (!isTokenValid(oldToken)) {
//	                throw new MyBusinessProException("Invalid or expired token.");
//	            }
//
//	            String username = extractUsername(oldToken);
//
//	            String hashedToken = hashToken(oldToken);
//
//	            redisTemplate.opsForValue().set(hashedToken, username, expiration, TimeUnit.MILLISECONDS);
//	            refreshData.put("refreshedToken", oldToken);
//	            return refreshData; 
//
//	        } catch (Exception e) {
//	            logger.error("Exception refreshToken failed: {}", oldToken, e);
//	            throw new MyBusinessProException("Exception error refreshToken ", e.getMessage());
//	        }
//	    }
	    
//	    option2 -> Sliding session without generating new JWT
//	    public Map<String,String> refreshToken(String token) {
//	    	Map<String,String> refreshData = new HashMap<String,String>();
//	        try {
//	        	validateJwtSignature(token); 
//
//	            String username = extractUsername(token);
//	            String hashedToken = hashToken(token);
//
//	            Boolean exists = redisTemplate.hasKey(hashedToken);
//	            if (Boolean.FALSE.equals(exists)) {
//	                throw new MyBusinessProException("Token revoked or not found.");
//	            }
//
//	            Long ttl = redisTemplate.getExpire(hashedToken, TimeUnit.MILLISECONDS);
//	            if (ttl == null || ttl <= 0) {
//	                throw new MyBusinessProException("Token expired.");
//	            }
//
//	            redisTemplate.expire(
//	                hashedToken,
//	                expiration,
//	                TimeUnit.MILLISECONDS
//	            );
//
//	            logger.info("Token refreshed successfully for user {}", username);
//	            refreshData.put("refreshedToken", token);
//	            refreshData.put("ttl", String.valueOf(ttl));
//	            return refreshData;
//
//	        } catch (Exception e) {
//	            logger.error("refreshToken failed", e);
//	            throw new MyBusinessProException("refreshToken ->", e.getMessage());
//	        }
//	    }
//	    
//	    public void validateJwtSignature(String token) {
//	        try {
//	            Jwts.parserBuilder()
//	                .setSigningKey(getSigningKey()) 
//	                .build()
//	                .parseClaimsJws(token); 
//	        } catch (JwtException e) {
//	            throw new MyBusinessProException("Invalid token signature ->", e.getMessage());
//	        }
//	    }



	    
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


