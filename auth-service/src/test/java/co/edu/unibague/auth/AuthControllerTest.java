package co.edu.unibague.auth;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Pruebas de integración de auth-service con una base H2 en memoria. */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:authtest;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop"
})
@AutoConfigureMockMvc
class AuthControllerTest {

    @Autowired
    MockMvc mvc;

    private static String credentials(String username, String password) {
        return "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
    }

    private static String uniqueUser() {
        return "user" + UUID.randomUUID().toString().substring(0, 8);
    }

    private ResultActions send(String path, String body) throws Exception {
        return mvc.perform(MockMvcRequestBuilders.post(path)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    private String loginToken(String username, String password) throws Exception {
        String body = send("/api/auth/login", credentials(username, password))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(body, "$.access_token");
    }

    @Test
    void registerCreatesUserWithUserRole() throws Exception {
        String user = uniqueUser();
        send("/api/auth/register", credentials(user, "Password123"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value(user))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    void registerDuplicateUserReturnsConflict() throws Exception {
        String user = uniqueUser();
        send("/api/auth/register", credentials(user, "Password123")).andExpect(status().isCreated());
        send("/api/auth/register", credentials(user, "Password123")).andExpect(status().isConflict());
    }

    @Test
    void registerWithShortPasswordReturnsBadRequest() throws Exception {
        send("/api/auth/register", credentials(uniqueUser(), "corta"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginReturnsOAuth2TokenResponse() throws Exception {
        String user = uniqueUser();
        send("/api/auth/register", credentials(user, "Password123")).andExpect(status().isCreated());

        send("/api/auth/login", credentials(user, "Password123"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(3600));
    }

    @Test
    void loginWithWrongPasswordReturnsUnauthorized() throws Exception {
        String user = uniqueUser();
        send("/api/auth/register", credentials(user, "Password123")).andExpect(status().isCreated());

        send("/api/auth/login", credentials(user, "OtraClave999")).andExpect(status().isUnauthorized());
    }

    @Test
    void tokenIsSignedWithRs256AndVerifiableWithPublishedJwks() throws Exception {
        String user = uniqueUser();
        send("/api/auth/register", credentials(user, "Password123")).andExpect(status().isCreated());
        String token = loginToken(user, "Password123");

        String jwks = mvc.perform(MockMvcRequestBuilders.get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        RSAKey publicKey = JWKSet.parse(jwks).getKeys().get(0).toRSAKey();
        assertThat(publicKey.isPrivate()).as("el JWKS no debe exponer la llave privada").isFalse();

        SignedJWT jwt = SignedJWT.parse(token);
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
        assertThat(jwt.verify(new RSASSAVerifier(publicKey))).isTrue();
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo(user);
        assertThat(jwt.getJWTClaimsSet().getStringListClaim("roles")).containsExactly("USER");
    }

    @Test
    void seededAdminGetsAdminRole() throws Exception {
        String token = loginToken("admin", "Admin12345!");
        SignedJWT jwt = SignedJWT.parse(token);
        assertThat(jwt.getJWTClaimsSet().getStringListClaim("roles")).containsExactly("ADMIN");
    }

    @Test
    void unknownRoutesAreDenied() throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/api/otra-ruta"))
                .andExpect(status().is4xxClientError());
    }
}
