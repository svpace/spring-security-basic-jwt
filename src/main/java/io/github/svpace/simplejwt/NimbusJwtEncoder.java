/*
 * Copyright 2020-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.svpace.simplejwt;

import java.util.Collections;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.util.Assert;

import com.nimbusds.jose.Header;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import net.minidev.json.JSONObject;

public class NimbusJwtEncoder implements JwtEncoder {
    private static final String DECODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to encode the Jwt: %s";

    private Converter<Map<String, Object>, Map<String, Object>> claimSetConverter = MappedJwtClaimSetConverter
	.withDefaults(Collections.emptyMap());

    private final JWEEncrypter jweEncrypter;

    private final JWSSigner jwsSigner;

    public NimbusJwtEncoder(JWSSigner jwsSigner, JWEEncrypter jweEncrypter) {
	this.jwsSigner = jwsSigner;
	this.jweEncrypter = jweEncrypter;
    }

    public void setClaimSetConverter(Converter<Map<String, Object>, Map<String, Object>> claimSetConverter) {
	Assert.notNull(claimSetConverter, "claimSetConverter cannot be null");
	this.claimSetConverter = claimSetConverter;
    }

    @Override
    public String encode(Jwt jwt) throws JwtException {
	try {
	    var header = Header.parse(new JSONObject(jwt.getHeaders()));
	    var claims = JWTClaimsSet.parse(new JSONObject(claimSetConverter.convert(jwt.getClaims())));
	    var token = createJwt(header, claims);
	    return token.serialize();
	} catch (Exception ex) {
	    throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
	}
    }

    private JWT createJwt(Header header, JWTClaimsSet claims) throws JOSEException {
	if (header instanceof PlainHeader) {
	    return new PlainJWT((PlainHeader) header, claims);
	} else if (header instanceof JWSHeader) {
	    var jws = new SignedJWT((JWSHeader) header, claims);
	    jws.sign(jwsSigner);
	    return jws;
	} else if (header instanceof JWEHeader) {
	    var jwe = new EncryptedJWT((JWEHeader) header, claims);
	    jwe.encrypt(jweEncrypter);
	    return jwe;
	} else {
	    throw new AssertionError("Unexpected algorithm type: " + header.getAlgorithm());
	}
    }

//    	public static JwkSetUriJwtEncoderBuilder withJwkSetUri(String jwkSetUri) {
//   		return new JwkSetUriJwtEncoderBuilder(jwkSetUri);
//    	}

//    	public static PublicKeyJwtEncoderBuilder withPublicKey(RSAPublicKey key) {
//    		return new PublicKeyJwtEncoderBuilder(key);
//    	}

    public static SecretKeyJwtEncoderBuilder withSecretKey(SecretKey secretKey) {
	return new SecretKeyJwtEncoderBuilder(secretKey);
    }

//    	public static final class JwkSetUriJwtEncoderBuilder {
//    		private String jwkSetUri;
//    		private Set<SignatureAlgorithm> signatureAlgorithms = new HashSet<>();
//    		private RestOperations restOperations = new RestTemplate();
//
//    		private JwkSetUriJwtEncoderBuilder(String jwkSetUri) {
//    			Assert.hasText(jwkSetUri, "jwkSetUri cannot be empty");
//    			this.jwkSetUri = jwkSetUri;
//    		}
//
//    		public JwkSetUriJwtEncoderBuilder jwsAlgorithm(SignatureAlgorithm signatureAlgorithm) {
//    			Assert.notNull(signatureAlgorithm, "signatureAlgorithm cannot be null");
//    			this.signatureAlgorithms.add(signatureAlgorithm);
//    			return this;
//    		}
//
//    		public JwkSetUriJwtEncoderBuilder jwsAlgorithms(Consumer<Set<SignatureAlgorithm>> signatureAlgorithmsConsumer) {
//    			Assert.notNull(signatureAlgorithmsConsumer, "signatureAlgorithmsConsumer cannot be null");
//    			signatureAlgorithmsConsumer.accept(this.signatureAlgorithms);
//    			return this;
//    		}
//
//    		public JwkSetUriJwtEncoderBuilder restOperations(RestOperations restOperations) {
//    			Assert.notNull(restOperations, "restOperations cannot be null");
//    			this.restOperations = restOperations;
//    			return this;
//    		}
//
//    		JWSKeySelector<SecurityContext> jwsKeySelector(JWKSource<SecurityContext> jwkSource) {
//    			if (this.signatureAlgorithms.isEmpty()) {
//    				return new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);
//    			} else if (this.signatureAlgorithms.size() == 1) {
//    				JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(this.signatureAlgorithms.iterator().next().getName());
//    				return new JWSVerificationKeySelector<>(jwsAlgorithm, jwkSource);
//    			} else {
//    				Map<JWSAlgorithm, JWSKeySelector<SecurityContext>> jwsKeySelectors = new HashMap<>();
//    				for (SignatureAlgorithm signatureAlgorithm : this.signatureAlgorithms) {
//    					JWSAlgorithm jwsAlg = JWSAlgorithm.parse(signatureAlgorithm.getName());
//    					jwsKeySelectors.put(jwsAlg, new JWSVerificationKeySelector<>(jwsAlg, jwkSource));
//    				}
//    				return new JWSAlgorithmMapJWSKeySelector<>(jwsKeySelectors);
//    			}
//    		}
//
//    		JWTProcessor<SecurityContext> processor() {
//    			ResourceRetriever jwkSetRetriever = new RestOperationsResourceRetriever(this.restOperations);
//    			JWKSource<SecurityContext> jwkSource = new RemoteJWKSet<>(toURL(this.jwkSetUri), jwkSetRetriever);
//    			ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
//    			jwtProcessor.setJWSKeySelector(jwsKeySelector(jwkSource));
//
//    			// Spring Security validates the claim set independent from Nimbus
//    			jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> { });
//
//    			return jwtProcessor;
//    		}
//
//    		public NimbusJwtEncoder build() {
//    			return new NimbusJwtEncoder(processor());
//    		}
//
//    		private static URL toURL(String url) {
//    			try {
//    				return new URL(url);
//    			} catch (MalformedURLException ex) {
//    				throw new IllegalArgumentException("Invalid JWK Set URL \"" + url + "\" : " + ex.getMessage(), ex);
//    			}
//    		}
//
//    		private static class RestOperationsResourceRetriever implements ResourceRetriever {
//    			private static final MediaType APPLICATION_JWK_SET_JSON = new MediaType("application", "jwk-set+json");
//    			private final RestOperations restOperations;
//
//    			RestOperationsResourceRetriever(RestOperations restOperations) {
//    				Assert.notNull(restOperations, "restOperations cannot be null");
//    				this.restOperations = restOperations;
//    			}
//
//    			@Override
//    			public Resource retrieveResource(URL url) throws IOException {
//    				HttpHeaders headers = new HttpHeaders();
//    				headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON, APPLICATION_JWK_SET_JSON));
//
//    				ResponseEntity<String> response;
//    				try {
//    					RequestEntity<Void> request = new RequestEntity<>(headers, HttpMethod.GET, url.toURI());
//    					response = this.restOperations.exchange(request, String.class);
//    				} catch (Exception ex) {
//    					throw new IOException(ex);
//    				}
//
//    				if (response.getStatusCodeValue() != 200) {
//    					throw new IOException(response.toString());
//    				}
//
//    				return new Resource(response.getBody(), "UTF-8");
//    			}
//    		}
//    	}

//    public static final class PublicKeyJwtEncoderBuilder {
//	private JWSAlgorithm jwsAlgorithm;
//	private RSAPublicKey key;
//
//	private PublicKeyJwtEncoderBuilder(RSAPublicKey key) {
//	    Assert.notNull(key, "key cannot be null");
//	    this.jwsAlgorithm = JWSAlgorithm.RS256;
//	    this.key = key;
//	}
//
//	public PublicKeyJwtEncoderBuilder signatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
//	    Assert.notNull(signatureAlgorithm, "signatureAlgorithm cannot be null");
//	    this.jwsAlgorithm = JWSAlgorithm.parse(signatureAlgorithm.getName());
//	    return this;
//	}
//
//	JWTProcessor<SecurityContext> processor() {
//	    if (!JWSAlgorithm.Family.RSA.contains(this.jwsAlgorithm)) {
//		throw new IllegalStateException(
//		    "The provided key is of type RSA; " + "however the signature algorithm is of some other type: "
//			+ this.jwsAlgorithm + ". Please indicate one of RS256, RS384, or RS512."
//		);
//	    }
//
//	    JWSKeySelector<SecurityContext> jwsKeySelector = new SingleKeyJWSKeySelector<>(this.jwsAlgorithm, this.key);
//	    DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
//	    jwtProcessor.setJWSKeySelector(jwsKeySelector);
//
//	    jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
//	    });
//
//	    return jwtProcessor;
//	}
//
//	public NimbusJwtEncoder build() {
//	    return new NimbusJwtEncoder(processor());
//	}
//    }

    public static final class SecretKeyJwtEncoderBuilder {
	private final SecretKey secretKey;

	private SecretKeyJwtEncoderBuilder(SecretKey secretKey) {
	    Assert.notNull(secretKey, "secretKey cannot be null");
	    this.secretKey = secretKey;
	}

	public NimbusJwtEncoder build() throws KeyLengthException {
	    return new NimbusJwtEncoder(signer(), encrypter());
	}

	JWSSigner signer() throws KeyLengthException {
	    return new MACSigner(secretKey);
	}

	JWEEncrypter encrypter() throws KeyLengthException {
	    return new DirectEncrypter(secretKey);
	}
    }
}
