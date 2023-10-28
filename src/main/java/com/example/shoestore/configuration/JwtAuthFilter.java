package com.example.shoestore.configuration;

import com.example.shoestore.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        // Получаем заголовок "Authorization" из запроса, который содержит JWT токен
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // Проверяем, если заголовок пуст или не начинается с "Bearer ", то просто передаем запрос дальше
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return;
        }

        // Извлекаем JWT токен, убирая "Bearer " из начала
        jwt = authHeader.substring(7);

        // Извлекаем из токена имя пользователя (email)
        userEmail = jwtService.extractUsername(jwt);

        // Если имя пользователя извлечено и в текущем контексте безопасности нет аутентификации, то выполняем аутентификацию
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            // Получаем информацию о пользователе по его имени пользователя
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // Если JWT токен действителен для данного пользователя, создаем аутентификационный токен
            if(jwtService.isTokenValid(jwt, userDetails)){
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null, // Пароль (null, так как JWT не содержит пароля)
                        userDetails.getAuthorities()
                );

                // Устанавливаем информацию о запросе для аутентификационного токена
                authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // Устанавливаем аутентификацию в текущем контексте безопасности
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        // Передаем запрос дальше в цепь фильтров
        filterChain.doFilter(request, response);
    }
}
