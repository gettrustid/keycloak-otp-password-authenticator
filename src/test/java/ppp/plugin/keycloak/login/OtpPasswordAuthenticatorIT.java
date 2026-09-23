package ppp.plugin.keycloak.login;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.http.Fault;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.Testcontainers;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OtpPasswordAuthenticatorIT {

  private static final int OTP_SERVICE_PORT = 18089;
  private static final String REALM = "otp-password-test";
  private static final String CLIENT_ID = "test-client";
  private static final String CLIENT_SECRET = "test-secret";
  private static final String USERNAME = "alice";
  private static final String PASSWORD = "alice-password";

  private static WireMockServer otpService;
  private static KeycloakContainer keycloak;

  @BeforeAll
  static void startInfrastructure() {
    otpService = new WireMockServer(options().port(OTP_SERVICE_PORT));
    otpService.start();

    Testcontainers.exposeHostPorts(OTP_SERVICE_PORT);

    keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:26.2.1")
        .withProviderClassesFrom("target/classes")
        .withRealmImportFile("otp-password-test-realm.json");
    keycloak.start();
  }

  @AfterAll
  static void stopInfrastructure() {
    if (keycloak != null) {
      keycloak.stop();
    }
    if (otpService != null) {
      otpService.stop();
    }
  }

  @AfterEach
  void resetOtpService() {
    otpService.resetAll();
  }

  @Test
  void passwordGrant_withValidPassword_returnsToken() throws Exception {
    HttpResponse<String> response = requestToken(orderedMap(
        "grant_type", "password",
        "username", USERNAME,
        "password", PASSWORD));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("access_token"));
  }

  @Test
  void passwordGrant_withInvalidPassword_returnsUnauthorized() throws Exception {
    HttpResponse<String> response = requestToken(orderedMap(
        "grant_type", "password",
        "username", USERNAME,
        "password", "wrong-password"));

    assertEquals(401, response.statusCode());
  }

  @Test
  void otpGrant_withValidOtp_returnsToken() throws Exception {
    otpService.stubFor(post(urlEqualTo("/api/validateOtp")).willReturn(aResponse().withStatus(200)));

    HttpResponse<String> response = requestToken(orderedMap(
        "grant_type", "password",
        "username", USERNAME,
        "totp", "123456",
        "login-with-otp", "true"));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("access_token"));
  }

  @Test
  void otpGrant_withInvalidOtp_returnsUnauthorized() throws Exception {
    otpService.stubFor(post(urlEqualTo("/api/validateOtp")).willReturn(aResponse().withStatus(401)));

    HttpResponse<String> response = requestToken(orderedMap(
        "grant_type", "password",
        "username", USERNAME,
        "totp", "000000",
        "login-with-otp", "true"));

    assertEquals(401, response.statusCode());
    otpService.verify(1, postRequestedFor(urlEqualTo("/api/validateOtp")));
  }

  @Test
  void otpGrant_whenOtpServiceUnreachable_returnsUnauthorized() throws Exception {
    otpService.stubFor(post(urlEqualTo("/api/validateOtp"))
        .willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));

    HttpResponse<String> response = requestToken(orderedMap(
        "grant_type", "password",
        "username", USERNAME,
        "totp", "123456",
        "login-with-otp", "true"));

    assertEquals(401, response.statusCode());
    otpService.verify(1, postRequestedFor(urlEqualTo("/api/validateOtp")));
  }

  static HttpResponse<String> requestToken(Map<String, String> formParams) throws Exception {
    StringBuilder body = new StringBuilder();
    body.append("client_id=").append(CLIENT_ID);
    body.append("&client_secret=").append(CLIENT_SECRET);
    formParams.forEach((key, value) -> body.append("&").append(key).append("=").append(value));

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(keycloak.getAuthServerUrl() + "/realms/" + REALM + "/protocol/openid-connect/token"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
        .build();

    return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
  }

  static Map<String, String> orderedMap(String... keyValuePairs) {
    Map<String, String> map = new LinkedHashMap<>();
    for (int i = 0; i < keyValuePairs.length; i += 2) {
      map.put(keyValuePairs[i], keyValuePairs[i + 1]);
    }
    return map;
  }
}
