package ppp.plugin.keycloak.login;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.http.Fault;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.UserCredentialManager;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.ws.rs.core.Response;

import java.util.HashMap;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OtpPasswordAuthenticatorTest {

  private final OtpPasswordAuthenticator authenticator = new OtpPasswordAuthenticator();

  @Mock
  private AuthenticationFlowContext context;
  @Mock
  private HttpRequest httpRequest;
  @Mock
  private MultivaluedMap<String, String> formParams;
  @Mock
  private UserModel user;
  @Mock
  private UserCredentialManager credentialManager;
  @Mock
  private EventBuilder eventBuilder;
  @Mock
  private AuthenticatorConfigModel configModel;

  private static WireMockServer otpService;

  @BeforeAll
  static void startOtpService() {
    otpService = new WireMockServer(options().dynamicPort());
    otpService.start();
  }

  @AfterAll
  static void stopOtpService() {
    otpService.stop();
  }

  @AfterEach
  void resetOtpService() {
    otpService.resetAll();
  }

  @Test
  void retrievePassword_returnsPasswordFormParameter() {
    when(context.getHttpRequest()).thenReturn(httpRequest);
    when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
    when(formParams.getFirst("password")).thenReturn("secret");

    assertEquals("secret", authenticator.retrievePassword(context));
  }

  @Test
  void retrieveLoginWithOtp_returnsLoginWithOtpFormParameter() {
    when(context.getHttpRequest()).thenReturn(httpRequest);
    when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
    when(formParams.getFirst("login-with-otp")).thenReturn("true");

    assertEquals("true", authenticator.retrieveLoginWithOtp(context));
  }

  @Test
  void retrieveOtp_returnsTotpFormParameter() {
    when(context.getHttpRequest()).thenReturn(httpRequest);
    when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
    when(formParams.getFirst("totp")).thenReturn("123456");

    assertEquals("123456", authenticator.retrieveOtp(context));
  }

  @Test
  void authenticate_withoutLoginWithOtp_andValidPassword_succeeds() {
    stubFormParams(null, "correct-password", null);
    when(context.getUser()).thenReturn(user);
    when(user.credentialManager()).thenReturn(credentialManager);
    when(credentialManager.isValid(any(CredentialInput.class))).thenReturn(true);

    authenticator.authenticate(context);

    verify(context).success();
    verify(context, never()).failure(any(), any());
  }

  @Test
  void authenticate_withoutLoginWithOtp_andInvalidPassword_fails() {
    stubFormParams(null, "wrong-password", null);
    when(context.getUser()).thenReturn(user);
    when(user.credentialManager()).thenReturn(credentialManager);
    when(credentialManager.isValid(any(CredentialInput.class))).thenReturn(false);
    when(context.getEvent()).thenReturn(eventBuilder);

    authenticator.authenticate(context);

    verify(context).failure(eq(AuthenticationFlowError.INVALID_USER), any(Response.class));
    verify(context, never()).success();
  }

  @Test
  void authenticate_withLoginWithOtpFalse_treatsAsPasswordFlow() {
    stubFormParams("false", "correct-password", null);
    when(context.getUser()).thenReturn(user);
    when(user.credentialManager()).thenReturn(credentialManager);
    when(credentialManager.isValid(any(CredentialInput.class))).thenReturn(true);

    authenticator.authenticate(context);

    verify(context).success();
  }

  private void stubFormParams(String loginWithOtp, String password, String totp) {
    lenient().when(context.getHttpRequest()).thenReturn(httpRequest);
    lenient().when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
    lenient().when(formParams.getFirst("login-with-otp")).thenReturn(loginWithOtp);
    lenient().when(formParams.getFirst("password")).thenReturn(password);
    lenient().when(formParams.getFirst("totp")).thenReturn(totp);
  }

  @Test
  void authenticate_withLoginWithOtpTrue_andOtpServiceReturns200_succeeds() {
    otpService.stubFor(post(urlEqualTo("/api/validateOtp")).willReturn(aResponse().withStatus(200)));
    stubFormParams("true", null, "123456");
    when(context.getUser()).thenReturn(user);
    when(user.getUsername()).thenReturn("alice");
    when(context.getAuthenticatorConfig()).thenReturn(configModel);
    when(configModel.getConfig()).thenReturn(configWithUrl());

    authenticator.authenticate(context);

    verify(context).success();
    verify(context, never()).failure(any(), any());
  }

  @Test
  void authenticate_withLoginWithOtpTrue_andOtpServiceReturns401_fails() {
    otpService.stubFor(post(urlEqualTo("/api/validateOtp")).willReturn(aResponse().withStatus(401)));
    stubFormParams("true", null, "000000");
    when(context.getUser()).thenReturn(user);
    when(user.getUsername()).thenReturn("alice");
    when(context.getAuthenticatorConfig()).thenReturn(configModel);
    when(configModel.getConfig()).thenReturn(configWithUrl());
    when(context.getEvent()).thenReturn(eventBuilder);

    authenticator.authenticate(context);

    verify(context).failure(eq(AuthenticationFlowError.INVALID_USER), any(Response.class));
    verify(context, never()).success();
  }

  @Test
  void authenticate_withLoginWithOtpTrue_andOtpServiceUnreachable_fails() {
    otpService.stubFor(post(urlEqualTo("/api/validateOtp"))
        .willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
    stubFormParams("true", null, "123456");
    when(context.getUser()).thenReturn(user);
    when(user.getUsername()).thenReturn("alice");
    when(context.getAuthenticatorConfig()).thenReturn(configModel);
    when(configModel.getConfig()).thenReturn(configWithUrl());
    when(context.getEvent()).thenReturn(eventBuilder);

    authenticator.authenticate(context);

    verify(context).failure(eq(AuthenticationFlowError.INVALID_USER), any(Response.class));
  }

  private Map<String, String> configWithUrl() {
    Map<String, String> config = new HashMap<>();
    config.put("otp-validation-service-url", otpService.baseUrl() + "/api/validateOtp");
    return config;
  }

  @Test
  void requiresUser_returnsTrue() {
    assertTrue(authenticator.requiresUser());
  }

  @Test
  void configuredFor_returnsTrue() {
    assertTrue(authenticator.configuredFor(null, null, null));
  }

  @Test
  void setRequiredActions_doesNothing() {
    authenticator.setRequiredActions(null, null, null);
  }

  @Test
  void isUserSetupAllowed_returnsFalse() {
    assertFalse(authenticator.isUserSetupAllowed());
  }

  @Test
  void getDisplayType_returnsPasswordOtp() {
    assertEquals("PasswordOtp", authenticator.getDisplayType());
  }

  @Test
  void getReferenceCategory_returnsNull() {
    assertNull(authenticator.getReferenceCategory());
  }

  @Test
  void isConfigurable_returnsFalse() {
    assertFalse(authenticator.isConfigurable());
  }

  @Test
  void getRequirementChoices_returnsNonEmptyArray() {
    assertTrue(authenticator.getRequirementChoices().length > 0);
  }

  @Test
  void getHelpText_returnsDescription() {
    assertEquals(
        "Validates the password supplied as a 'password' or otp form parameter in direct grant request",
        authenticator.getHelpText());
  }

  @Test
  void getConfigProperties_returnsEmptyList() {
    assertTrue(authenticator.getConfigProperties().isEmpty());
  }

  @Test
  void getId_returnsProviderId() {
    assertEquals("direct-grant-validate-otp-password", authenticator.getId());
  }
}
