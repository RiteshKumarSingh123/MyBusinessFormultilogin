package com.business.busi.configuration;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@Component
public class JwtService {

	@Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;
	
//	 private final String SECRET_KEY = "0123456789012345678901234567890101234567890123456789012345678901";
//    
//     private final long EXPIRATION_TIME = 864_000_00L;

    
    @Autowired
    private StringRedisTemplate redisTemplate;
    
    
	   
	    public String generateToken(String username) {
	        Map<String, Object> claims = new HashMap<>();
	        return createToken(claims, username);
	    }

	    private  String createToken(Map<String, Object> claims, String username) {

	        String token = Jwts.builder()
	                .setClaims(claims)
	                .setSubject(username)
	                .setIssuedAt(new Date())
	                .setExpiration(new Date(System.currentTimeMillis() + expiration))
	                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
	                .compact();
	        
	        String userKey = "user:" + username;  // e.g. user:john_doe
		     String oldToken = redisTemplate.opsForValue().get(userKey);

		   
		     if (oldToken != null) {
		         redisTemplate.delete(oldToken);
		         redisTemplate.delete(userKey);  
		     }

		     redisTemplate.opsForValue().set(token, username, expiration, TimeUnit.MILLISECONDS);

		     
		     redisTemplate.opsForValue().set(userKey, token, expiration, TimeUnit.MILLISECONDS);
	        
	        return token;
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
	  
	    public boolean validateToken(String token, UserDetails userDetails) {
	        try {
	            final String username = extractUsername(token);
	            if (!username.equals(userDetails.getUsername()) || isTokenExpired(token)) {
	                return false;
	            }
	            String cachedToken = redisTemplate.opsForValue().get("user:" + username);
	            return cachedToken != null && cachedToken.equals(token);

	        } catch (JwtException e) {
	            return false;
	        }
	    }


	    private  boolean isTokenExpired(String token) {
	        return extractClaim(token, Claims::getExpiration).before(new Date());
	    }
	    
	    public boolean isTokenValid(String token) {
	        return redisTemplate.hasKey(token);
	    }
	    
	    public void deleteToken(String token) {
	    	 String username = redisTemplate.opsForValue().get(token);
	         if (username != null) {
	             redisTemplate.delete("user:" + username); // remove user -> token
	         }
	        redisTemplate.delete(token);
	    }

    
	
}


