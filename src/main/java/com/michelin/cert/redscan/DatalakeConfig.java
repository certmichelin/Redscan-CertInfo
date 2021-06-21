/**
 * Michelin CERT 2020.
 */

package com.michelin.cert.redscan;

import com.michelin.cert.redscan.utils.datalake.DatalakeStorage;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * Configure ElasticSearch datalake.
 *
 * @author Maxime ESCOURBIAC
 */
@Configuration
public class DatalakeConfig extends DatalakeStorage {

  @Value("${datalake.elastic.url}")
  private String elasticSearchUrlProperty;

  @Autowired
  public DatalakeConfig() {
    super();
  }

  @PostConstruct
  public void initDatalakeStorage() {
    elasticSearchUrl = elasticSearchUrlProperty;
  }

}
