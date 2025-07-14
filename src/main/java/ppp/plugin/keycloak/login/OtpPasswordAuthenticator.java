package ppp.plugin.keycloak.login;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.models.*;
import org.keycloak.events.Errors;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.provider.ProviderConfigProperty;
import org.jboss.logging.Logger;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.MultivaluedMap;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class OtpPasswordAuthenticator extends AbstractDirectGrantAuthenticator {

  private static final Logger logger = Logger.getLogger(OtpPasswordAuthenticator.class);
  private static final String OTP_PASSWORD_CONDITIONAL_USER_ATTRIBUTE = "login-with-otp";
  public static final String PROVIDER_ID = "direct-grant-validate-otp-password";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    String loginWithOtp = retrieveLoginWithOtp(context);
    // Normal login with password code
    if (loginWithOtp == null || !"true".equalsIgnoreCase(loginWithOtp)) {
      String password = retrievePassword(context);
      boolean valid = context.getUser().credentialManager().isValid(UserCredentialModel.password(password));
      if (!valid) {
        context.getEvent().user(context.getUser());
        context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
        Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
            "invalid_grant", "Invalid user credentials");
        context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
        return;
      }
      context.success();
    }
    // Login with OTP flow
    else {
      boolean success = validateOTP(context);
      if (success) {
        context.success();
      } else {
        context.getEvent().user(context.getUser());
        context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
        Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
            "invalid_grant", "Invalid user credentials");
        context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
      }
    }
  }

  private boolean validateOTP(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    logger.debug("verify-login-otp for " + user.getUsername());
    String totp = retrieveOtp(context);
    String url = getOtpValidationUrl(context);
    logger.debug("verify-login-otp url=" + url);

    boolean success = restCall(url, user.getUsername(), totp);
    if (success) {
      logger.info("verify-login-otp for " + user.getUsername() + " successful");
    } else {
      logger.info("loginWithOtp for " + user.getUsername() + " fail");
    }
    return success;
  }

  private boolean restCall(String url, String mobileNo, String otp) {
    try {
      HttpClient client = HttpClient.newHttpClient();
      String jsonRequest = String.format("{ \"otp\": \"%s\", \"username\": \"%s\" }", otp, mobileNo);
      logger.info("REQUESTED URL: " + url);
      HttpRequest request = HttpRequest.newBuilder()
          .uri(new URI(url))
          .timeout(java.time.Duration.ofSeconds(5))
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(jsonRequest))
          .build();

      HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

      int status = response.statusCode();

      return status == 200;
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }
  }

  private String getOtpValidationUrl(AuthenticationFlowContext context) {
    AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
    Map<String, String> config = configModel.getConfig();
    String url = config.get(OtpPasswordAuthenticatorFactory.OTP_VALIDATION_EXTERNAL_SERVICE_URL);
    return url;
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getDisplayType() {
    return "PasswordOtp";
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public String getHelpText() {
    return "Validates the password supplied as a 'password' or otp form parameter in direct grant request";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return new LinkedList<>();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  protected String retrievePassword(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
    return inputData.getFirst(CredentialRepresentation.PASSWORD);
  }

  protected String retrieveLoginWithOtp(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
    return inputData.getFirst(OTP_PASSWORD_CONDITIONAL_USER_ATTRIBUTE);
  }

  protected String retrieveOtp(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
    return inputData.getFirst(CredentialRepresentation.TOTP);
  }

}
