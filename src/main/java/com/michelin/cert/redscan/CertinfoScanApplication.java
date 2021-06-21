/**
 * Michelin CERT 2020.
 */


package com.michelin.cert.redscan;

import com.michelin.cert.redscan.utils.datalake.DatalakeStorageException;
import com.michelin.cert.redscan.utils.models.Alert;
import com.michelin.cert.redscan.utils.models.HttpService;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.apache.logging.log4j.LogManager;
import org.json.JSONObject;

import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


/**
 * RedScan scanner main class.
 *
 * @author Maxime ESCOURBIAC
 * @author Sylvain VAISSIER
 * @author Maxence SCHMITT
 */
@SpringBootApplication
public class CertinfoScanApplication {

  //Only required if pushing data to queues
  private final RabbitTemplate rabbitTemplate;

  @Autowired
  private DatalakeConfig datalakeConfig;

  /**
   * Constructor to init rabbit template. Only required if pushing data to queues
   *
   * @param rabbitTemplate Rabbit template.
   */
  public CertinfoScanApplication(RabbitTemplate rabbitTemplate) {
    this.rabbitTemplate = rabbitTemplate;
  }
  
  
  /**
   * RedScan Main methods.
   *
   * @param args Application arguments.
   */
  public static void main(String[] args) {
    SpringApplication.run(CertinfoScanApplication.class, args);
  }

  /**
   * Check if the certificate authority and certificate owner are the same = Selfsigned.
   * @param certificate the X509 Certficates
   * @return boolean The certificate is selfsigned or not.
   */
  private boolean isSelfSigned(X509Certificate certificate) {
    try {
      certificate.verify(certificate.getPublicKey());
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }
  /**
  * Extract Cerficates datas and stores it in a JSONObject.
  * @param cert The X509 certificate.
  * @param httpMessage the original RabbitMessage for retrieving url
  * @return obj JSON formated object
  */
  public JSONObject extractDatas(X509Certificate cert, HttpService httpMessage) {
    JSONObject obj = new JSONObject();
    obj.put("isSelfSigned", isSelfSigned(cert));
    obj.put("Deliver to",cert.getSubjectDN().getName());
    obj.put("Issuer", cert.getIssuerDN().getName());
    obj.put("Cipher", cert.getSigAlgName());
    Date notAfter = cert.getNotAfter();
    checkDate(notAfter,httpMessage.toUrl());
    obj.put("notAfter", notAfter.toString());
    return obj;
    
  }
  /**
   * Check Date validity and send alert accordingly.
   * @param date the notAfter expiry date of the certificate.
   * @param url The url of the domain
   */
  public void checkDate(Date date, String url) {
    Date today = Calendar.getInstance().getTime();
    if (date.before(today)) {
      Alert alert = new Alert(3, "Selfsigned Certficate", "Certificate is self signed", url, "Certinfo");
      rabbitTemplate.convertAndSend(RabbitMqConfig.FANOUT_ALERTS_EXCHANGE_NAME, "", alert.toJson());
    }
    
  }
  /**
   * Message executor.
   *
   * @param message Message received.
   */
  @RabbitListener(queues = {RabbitMqConfig.QUEUE_HTTP_SERVICES})
  public void receiveMessage(String message) {
    HttpService httpMessage = new HttpService(message);
    if (httpMessage.isSsl()) {
      LogManager.getLogger(CertinfoScanApplication.class).info(String.format("Retrieving certificate information on: %s", httpMessage.getDomain()));
      try {
        // Creating custom ssl context for retrieving certificate info on selfsigned certificate
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(new KeyManager[0], new TrustManager[]{new PermissiveTrustManager()}, new SecureRandom());
        SSLContext.setDefault(ctx);
        URL url = new URL(httpMessage.toUrl());
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        // Creating Custom Hostname verifier for accepting Unknwow Certificate Authority (like selfsigned)
        HostnameVerifier hostCheck = new PermissiveHostnameVerifier();
        conn.setHostnameVerifier(hostCheck);
        LogManager.getLogger(CertinfoScanApplication.class).info(String.format("Connecting..."));
        conn.connect();
        LogManager.getLogger(CertinfoScanApplication.class).info(String.format("Retrieving certificates...."));
        // First certificate is the principal, followed by Certificates Authorities.
        Certificate cert = conn.getServerCertificates()[0];
        if ((cert instanceof X509Certificate)) {
          LogManager.getLogger(CertinfoScanApplication.class).info(String.format("Certificate is %s", cert.toString()));
          X509Certificate xcert = (X509Certificate) cert;
          LogManager.getLogger(CertinfoScanApplication.class).info(String.format("Extracting datas"));
          JSONObject result = extractDatas(xcert,httpMessage);
          LogManager.getLogger(CertinfoScanApplication.class).info(String.format("Upserting data %s", result));
          datalakeConfig.upsertHttpServiceField(httpMessage.getDomain(), httpMessage.getPort(), "Certinfo", result);
        }

      } catch (IOException | NoSuchAlgorithmException | KeyManagementException | DatalakeStorageException ex) {
        LogManager.getLogger(CertinfoScanApplication.class).error(String.format("%s EXCEPTION : %s",ex.getClass(), ex.toString()));
      }
    } else {
      LogManager.getLogger(CertinfoScanApplication.class).warn(String.format("%s is not SSL", httpMessage.getDomain()));
    }
    
    
  }

}

