package io.github.svpace.simplejwt;

import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toSet;

import java.lang.reflect.Method;
import java.security.Principal;
import java.time.Duration;
import java.time.Instant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

@Configuration
@Order(1)
class BasicJwtConfiguration extends WebSecurityConfigurerAdapter {

    private final JwtEncoder jwtEncoder;

    public BasicJwtConfiguration(JwtEncoder jwtEncoder) {
	this.jwtEncoder = jwtEncoder;
    }

    @Autowired
    public void setHandlerMapping(RequestMappingHandlerMapping mapping)
	throws NoSuchMethodException, SecurityException {
	RequestMappingInfo info = RequestMappingInfo.paths("/api/authenticate").methods(RequestMethod.GET).build();
	Method method = BasicJwtConfiguration.class.getMethod("getToken");
	mapping.registerMapping(info, this, method);
    }

    public ResponseEntity<OAuth2AccessTokenResponse> getToken() throws JwtException {
	var auth = getAuthentication();
	var jwt = Jwt
	    .withTokenValue("")
	    .subject(auth.getName())
	    .expiresAt(Instant.now().plus(Duration.ofMinutes(1)))
	    .claim(OAuth2IntrospectionClaimNames.SCOPE, auth.getAuthorities().stream().map(it -> it.getAuthority()).collect(joining(" "))).build();
	var token = jwtEncoder.encode(jwt);
	var body = OAuth2AccessTokenResponse
	    .withToken(token)
	    .tokenType(OAuth2AccessToken.TokenType.BEARER)
	    .expiresIn(Duration.ofMinutes(1).toMillis())
	    .scopes(getAuthentication().getAuthorities().stream().map(it -> it.getAuthority()).collect(toSet()))
	    .build();
	return ResponseEntity.status(HttpStatus.OK).header("Authorization", "Bearer ${token}").body(body);

    }

    public static Authentication getAuthentication() {
	return getAuthentication(SecurityContextHolder.getContext().getAuthentication());
    }

    public static Authentication getAuthentication(Principal auth) {
	if (auth instanceof Authentication) {
	    return (Authentication) auth;
	} else {
	    throw new AuthenticationCredentialsNotFoundException("Invalid Credentials: $auth");
	}
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
	http.antMatcher("/api/authenticate");
	http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	http.httpBasic();
	http.authorizeRequests().anyRequest().authenticated();
    }
}
