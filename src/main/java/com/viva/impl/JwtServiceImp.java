package com.viva.impl;

import com.viva.service.JwtService;
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
public class JwtServiceImp implements JwtService {


    private  static final String SECRET_KEY = "d4dHyN7T80+YMC4aEspuSj3HLGyBGt9/npMIXKMkIz4MUascPekyerwiIsIv0yOJXdnEqWyUA0LqELgSCoXESv5GRk+DGDhOiT1eiMDM4lx0IwJ8fryMUoh6nnD3Yrv7r1y+WpvL8845dS7UjfgwDQ==";
    private long jwtExpiration;
    public String extractUsername(String token) {
        return extractClaim(token , Claims::getSubject);
    }
    public <T> T extractClaim(String token , Function<Claims , T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return  claimsResolver.apply(claims);
    }
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>() , userDetails);
    }
    public String generateToken(
            Map<String , Object> extractClaims,
            UserDetails userDetails
    ){
        return buildToken(extractClaims,userDetails,jwtExpiration);

    }
    public String generateRefreshToken( UserDetails userDetails){
        return  buildToken(new HashMap<>(),userDetails,jwtExpiration);
    }

    private  String buildToken(
            Map<String, Object> extractClaims,
            UserDetails userDetails,
            long expiration
    ){
        return Jwts
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey() , SignatureAlgorithm.HS256)
                .compact();
    }


    public boolean isTokenValid(String token , UserDetails userDetails){
        String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }
    public boolean isTokenExpired(String token){
        return  extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return  extractClaim(token , Claims::getExpiration);
    }


    private Claims extractAllClaims(String token) {
        // signing key is used to create signature which is used to verify the sender who send the token is who!!
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
