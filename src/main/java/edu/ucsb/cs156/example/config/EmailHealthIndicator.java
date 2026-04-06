package edu.ucsb.cs156.example.config;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

@Component
public class EmailHealthIndicator implements HealthIndicator {

  private final String adminEmails;

  private final PublicKey key;
  private final String encrypted_emails;

  public EmailHealthIndicator(@Value("${app.public_key}") String key, @Value("${app.admin.emails}") String adminEmails)
      throws Exception {
    X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    this.key = keyFactory.generatePublic(publicSpec);
    this.adminEmails = adminEmails;
    this.encrypted_emails = encrypt_emails();
  }

  @Override
  public Health health() {
    try {
      return Health.up().withDetail("email", this.encrypted_emails).build();
    } catch (Exception e) {
      return Health.down().withDetail("email", e.getMessage()).build();
    }
  }

  private String encrypt_emails() throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] cipherText = cipher.doFinal(adminEmails.getBytes());
    return Base64.getEncoder().encodeToString(cipherText);
  }
}
