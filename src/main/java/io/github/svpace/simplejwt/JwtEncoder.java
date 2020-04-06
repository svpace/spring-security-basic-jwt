package io.github.svpace.simplejwt;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

public interface JwtEncoder {

    String encode(Jwt token) throws JwtException;

}
