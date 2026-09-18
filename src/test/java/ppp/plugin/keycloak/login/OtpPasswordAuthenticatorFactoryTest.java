package ppp.plugin.keycloak.login;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OtpPasswordAuthenticatorFactoryTest {

  private final OtpPasswordAuthenticatorFactory factory = new OtpPasswordAuthenticatorFactory();

  @Test
  void create_returnsSameAuthenticatorInstanceEveryTime() {
    Authenticator first = factory.create(null);
    Authenticator second = factory.create(null);

    assertSame(first, second);
    assertTrue(first instanceof OtpPasswordAuthenticator);
  }

  @Test
  void getDisplayType_returnsExpectedLabel() {
    assertEquals("Otp Password Authenticator", factory.getDisplayType());
  }

  @Test
  void isConfigurable_returnsTrue() {
    assertTrue(factory.isConfigurable());
  }

  @Test
  void getRequirementChoices_returnsOnlyRequired() {
    AuthenticationExecutionModel.Requirement[] choices = factory.getRequirementChoices();

    assertEquals(1, choices.length);
    assertEquals(AuthenticationExecutionModel.Requirement.REQUIRED, choices[0]);
  }

  @Test
  void isUserSetupAllowed_returnsFalse() {
    assertFalse(factory.isUserSetupAllowed());
  }

  @Test
  void getHelpText_returnsDescription() {
    assertEquals("Limits access to only valid Otp or password", factory.getHelpText());
  }

  @Test
  void getConfigProperties_returnsOtpValidationUrlProperty() {
    List<ProviderConfigProperty> properties = factory.getConfigProperties();

    assertEquals(1, properties.size());
    ProviderConfigProperty urlProperty = properties.get(0);
    assertEquals(OtpPasswordAuthenticatorFactory.OTP_VALIDATION_EXTERNAL_SERVICE_URL, urlProperty.getName());
    assertEquals("OTP validation service url", urlProperty.getLabel());
    assertEquals("http://localhost:8080/api/validateOtp", urlProperty.getDefaultValue());
  }

  @Test
  void getReferenceCategory_returnsNull() {
    assertNull(factory.getReferenceCategory());
  }

  @Test
  void lifecycleMethods_doNotThrow() {
    factory.init(null);
    factory.postInit(null);
    factory.close();
  }

  @Test
  void getId_returnsExpectedProviderId() {
    assertEquals("otppasswordauthenticator", factory.getId());
  }
}
