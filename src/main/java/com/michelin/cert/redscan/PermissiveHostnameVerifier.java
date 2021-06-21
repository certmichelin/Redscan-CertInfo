/**
 * Michelin CERT 2020.
 */

package com.michelin.cert.redscan;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

/**
 * Allow to bypass hostname verification blocking connection to unknow CA webiste.
 * @author VAYSSIER Sylvain
 */
public class PermissiveHostnameVerifier implements HostnameVerifier{

  @Override
  public boolean verify(String string, SSLSession ssls) {
    return true;
  }
  
}
