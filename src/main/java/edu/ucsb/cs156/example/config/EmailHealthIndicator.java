package edu.ucsb.cs156.example.config;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class EmailHealthIndicator implements HealthIndicator {

  private final PublicKey key;
  private String encrypted_emails;

  public EmailHealthIndicator(@Value("${app.public_key}") String key, @Value("${app.admin.emails}") String adminEmails)
      throws Exception {
    X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    this.key = keyFactory.generatePublic(publicSpec);
    try{
      this.encrypted_emails = encrypt_emails(adminEmails);
    }catch(IllegalBlockSizeException e){
      log.error("Warning: List of admin emails is likely too long. If you are sure it is correct,"
          + "please contact the course staff.");
      this.encrypted_emails = null;
    }
  }

  @Override
  public Health health() {
    if (this.encrypted_emails == null) {
      return Health.down().build();
    }
      return Health.up().withDetail("email", this.encrypted_emails).build();
  }

  private String encrypt_emails(String adminEmails) throws Exception {
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] cipherText = cipher.doFinal(adminEmails.getBytes());
    return Base64.getEncoder().encodeToString(cipherText);
  }
}
