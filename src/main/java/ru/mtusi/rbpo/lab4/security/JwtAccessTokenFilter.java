package ru.mtusi.rbpo.lab4.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.mtusi.rbpo.lab4.model.AccountStatus;
import ru.mtusi.rbpo.lab4.model.User;
import ru.mtusi.rbpo.lab4.repository.UserRepository;

import java.io.IOException;
import java.util.Set;

@Component
public class JwtAccessTokenFilter extends OncePerRequestFilter {

    private static final Set<String> PUBLIC_TOKEN_ENDPOINTS = Set.of(
            "/auth/login", "/auth/register", "/auth/refresh");

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final RestAuthenticationEntryPoint authenticationEntryPoint;

    public JwtAccessTokenFilter(JwtService jwtService, UserRepository userRepository,
                                RestAuthenticationEntryPoint authenticationEntryPoint) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        if (path.isEmpty()) {
            path = request.getRequestURI().substring(request.getContextPath().length());
        }
        return PUBLIC_TOKEN_ENDPOINTS.contains(path);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer", 0, 6)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            if (authorization.length() <= 7 || authorization.charAt(6) != ' ') {
                throw new BadCredentialsException("Invalid access token");
            }
            String token = authorization.substring(7).trim();
            Jwt jwt = jwtService.validateAccessToken(token);
            User user = userRepository.findByUsernameIgnoreCase(jwt.getSubject())
                    .filter(candidate -> candidate.getAccountStatus() == AccountStatus.ACTIVE)
                    .orElseThrow(() -> new BadCredentialsException("Invalid access token"));
            UserPrincipal principal = new UserPrincipal(user);
            UsernamePasswordAuthenticationToken authentication =
                    UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            var context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
        } catch (JwtException | IllegalArgumentException | BadCredentialsException exception) {
            SecurityContextHolder.clearContext();
            authenticationEntryPoint.commence(request, response,
                    new BadCredentialsException("Invalid access token"));
            return;
        }
        filterChain.doFilter(request, response);
    }
}
