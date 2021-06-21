/**
 * Michelin CERT 2020.
 */

package com.michelin.cert.redscan;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

/**
 *
 * @author VAYSSIER Sylvain.
 */

/**
 * Allow connection on HTTPS with unknow CA.
 * @author VAYSSIER Sylvain
 */
public class PermissiveTrustManager implements X509TrustManager {

  @Override
  public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {}

  @Override
  public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {}

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return null;
  }
}