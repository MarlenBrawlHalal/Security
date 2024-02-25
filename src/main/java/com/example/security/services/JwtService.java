package com.example.security.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

  private final String SECRET_KEY = "1e694dd16b915250d44d681ed719b122383a5ab9d8fd42f18ab58fed29ffd877"; // Random-generated key for testing purpose

  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  private Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {

    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  public boolean isTokenValid(String token, UserDetails userDetails) {

    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
  }

  public String generateJwt(UserDetails userDetails) {
    return generateJwt(new HashMap<>(), userDetails);
  }

  public String generateJwt(
      Map<String, Object> extractClaims,
      UserDetails userDetails
  ) {
    return Jwts
        .builder()
        .setClaims(extractClaims)
        .setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
        .signWith(getSigningKey(), SignatureAlgorithm.HS256)
        .compact();
  }

  private boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  private Claims extractAllClaims(String token) {

    return Jwts
        .parserBuilder()
        .setSigningKey(getSigningKey())
        .build()
        .parseClaimsJws(token)
        .getBody();
  }

  private Key getSigningKey() {

    byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
