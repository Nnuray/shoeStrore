package com.example.shoestore.service;


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
import java.util.Objects;
import java.util.function.Function;

@Service

public class JwtService {
    private static final String SECRET_KEY = "j5GSGOShKWI/xZjwnYoUTGnA7qQpdfF+VjAZ6IOVs1b64e0oNQ6dcLnGVgslH+SrjIvCEmUMUC+NN5SGSWYWT8+wmI+Ced8A4mre3bkM4E6g3iE8wutA4qVnL32QHtARl9rmoJEYGOBak6bY1lt1DpnS/W3f4D+jDG4yhclAq32A1H6+gC7P6znv/OTT8AWnbBwOvJGsj1tdykKDVj1z60UlL3Ksc2ACHV+sUPVDJk9Bs4VgUV4wqn2NSlMaPsW6osXcq7f2rcKgxbN7FgmoYsT3S1jSnMGiHk966rUw/wA2fgssK3FT+62W5fqL1HV+52wZ6wTeXZAFkyBbRckf3VmIiPkadEIjelm+IDbbIiY=\n";

    public String extractUsername(String token) { // вернет строковое имя пользователя и примит токен
        return extractClaims(token, Claims::getSubject);
    }

    public <T> T extractClaims(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);   // чтобы извлечь все утверждения из токена
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Objects> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)  //дополнительные пользовательские данные
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis())) // дата выпуска (текущая дата)
                .setExpiration(new Date(System.currentTimeMillis() + 1000*60*24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)   // подписать токен с секретным ключом
                .compact(); // вернет токен

    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);  // проверка пользователя и срок токена
    }

    private boolean isTokenExpired(String token) { // извлекает дату истечения и сравнивает с текущей датой
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() { // чтобы получить код для подписи
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);  // байт передается и возвращает в виде key
    }
}