/**
 * Michelin CERT 2020.
 */

package com.michelin.cert.redscan;

import com.michelin.cert.redscan.utils.queueing.RabbitMqBaseConfig;

import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Declarables;
import org.springframework.amqp.core.FanoutExchange;
import org.springframework.amqp.core.Queue;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configure Rabbit MQ messages.
 *
 * @author Maxime ESCOURBIAC
 * @author Sylvain VAISSIER
 * @author Maxence SCHMITT
 */
@Configuration
public class RabbitMqConfig extends RabbitMqBaseConfig {

  //TODO: Configure interaction.
  
  ///**
  // * QUEUE_DOMAINS.
  // */
  public static final String QUEUE_HTTP_SERVICES = "com.michelin.cert.certinfo.http_services";

  /**
   * Queue configuration method.
   *
   * @return Declarables.
   */
  @Bean
  public Declarables fanoutBindings() {
    Queue queue = new Queue(QUEUE_HTTP_SERVICES, false);
    FanoutExchange fanoutExchange = new FanoutExchange(FANOUT_HTTP_SERVICES_EXCHANGE_NAME, false, false);
    return new Declarables(queue, fanoutExchange, BindingBuilder.bind(queue).to(fanoutExchange));
  }
}
