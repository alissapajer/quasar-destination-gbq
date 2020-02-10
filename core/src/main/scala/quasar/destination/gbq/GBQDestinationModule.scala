/*
 * Copyright 2014–2019 SlamData Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package quasar.destination.gbq

import slamdata.Predef._

import quasar.contrib.proxy.Search
import quasar.api.destination.{Destination, DestinationType, DestinationError}
import quasar.api.destination.DestinationError.InitializationError
import quasar.connector.{DestinationModule, MonadResourceErr}

import argonaut._, Argonaut._

import cats.effect.{
  Concurrent, 
  ConcurrentEffect, 
  ContextShift, 
  Resource, 
  Timer
}
import cats.data.EitherT
import cats.implicits._

import eu.timepit.refined.auto._

import java.net.{InetSocketAddress, ProxySelector}
import java.net.Proxy
import java.net.Proxy.{Type => ProxyType}

import org.asynchttpclient.proxy.{ProxyServer, ProxyServerSelector}
import org.asynchttpclient.{AsyncHttpClientConfig, DefaultAsyncHttpClientConfig}
import org.asynchttpclient.uri.{Uri => AUri}
import org.http4s.{
  AuthScheme,
  Credentials,
  Method,
  Request,
  Status,
  Uri}
import org.http4s.headers.Authorization
import org.http4s.client.Client
import org.http4s.client.asynchttpclient.AsyncHttpClient
import org.http4s.util.threads.threadFactory

import org.slf4s.Logging

import scala.util.Either
import scala.collection.JavaConverters._

import scalaz.NonEmptyList

object GBQDestinationModule extends DestinationModule with Logging {

  val Redacted: String = "<REDACTED>"

  def destinationType = DestinationType("gbq", 1L)

  def sanitizeDestinationConfig(config: Json): Json = {
    config.as[GBQConfig].toOption match {
      case Some(c) => c.copy(authCfg = Redacted).asJson
      case _ => jString(Redacted)
    }
  }

  def destination[F[_]: ConcurrentEffect: ContextShift: MonadResourceErr: Timer](
      config: Json)
      : Resource[F,Either[InitializationError[Json],Destination[F]]] = {

    val sanitizedConfig: Json = sanitizeDestinationConfig(config)
    val configOrError = config.as[GBQConfig].toEither.leftMap {
      case (err, _) =>
        DestinationError.malformedConfiguration((destinationType, jString(Redacted), err))
    }

    val init = for {
      cfg <- EitherT(Resource.pure[F, Either[InitializationError[Json], GBQConfig]](configOrError))
      client <- EitherT(mkClient.map(_.asRight[InitializationError[Json]]))
      _ <- EitherT(Resource.liftF(isLive(client, cfg, sanitizedConfig)))
    } yield new GBQDestination[F](client, cfg, sanitizedConfig): Destination[F]
    
    init.value
  }

  private def mkConfig[F[_]](proxySelector: ProxySelector): AsyncHttpClientConfig =
    new DefaultAsyncHttpClientConfig.Builder()
      .setMaxConnectionsPerHost(200)
      .setMaxConnections(400)
      .setRequestTimeout(Int.MaxValue)
      .setReadTimeout(Int.MaxValue)
      .setConnectTimeout(Int.MaxValue)
      .setProxyServerSelector(ProxyVoleProxyServerSelector(proxySelector))
      .setThreadFactory(threadFactory(name = { i =>
        s"http4s-async-http-client-worker-${i}"
      })).build

  private def mkClient[F[_]: ConcurrentEffect]: Resource[F, Client[F]] = {
    Resource.liftF(Search[F]).flatMap(selector =>
      AsyncHttpClient.resource(mkConfig(selector)))
  }

  private def isLive[F[_]: Concurrent: ContextShift](
      client: Client[F],
      config: GBQConfig,
      sanitizedConfig: Json)
      : F[Either[InitializationError[Json], Unit]] = {

    val req = for {
      accessToken <- GBQAccessToken.token(config.authCfg.getBytes("UTF-8"))
      auth = Authorization(Credentials.Token(AuthScheme.Bearer, accessToken.getTokenValue))
      request = Request[F](
        method = Method.GET,
        uri = Uri.fromString(s"https://www.googleapis.com/bigquery/v2/projects/${config.project}/datasets").getOrElse(Uri())
      ).withHeaders(auth)
    } yield request

    client.fetch(req) { resp =>
      resp.status match {
        case Status.Ok =>
          ().asRight[InitializationError[Json]].pure[F]
        case Status.NotFound =>
          DestinationError.invalidConfiguration(
            (destinationType, jString("Not Found"), 
            NonEmptyList(sanitizedConfig.toString))).asLeft.pure[F]
        case status =>
          DestinationError.malformedConfiguration(
            (destinationType, jString(status.reason), 
            sanitizedConfig.toString)).asLeft.pure[F]
      }
    }
  }

//// proxy config

  private def sortProxies(proxies: List[Proxy]): List[Proxy] = {
    proxies.sortWith((l, r) => (l.`type`, r.`type`) match {
      case (ProxyType.HTTP, ProxyType.DIRECT) => true
      case (ProxyType.SOCKS, ProxyType.DIRECT) => true
      case _ => false
    })
  }

  private case class ProxyVoleProxyServerSelector(selector: ProxySelector)
      extends ProxyServerSelector {
    def select(uri: AUri): ProxyServer = {
      ProxySelector.setDefault(selector) // NB: I don't think this is necessary

      Option(selector)
        .flatMap(s => Option(s.select(uri.toJavaNetURI)))
        .flatMap(proxies0 => {
          val proxies = proxies0.asScala.toList
          log.debug(s"Found proxies: $proxies")

          val sortedProxies = sortProxies(proxies)
          log.debug(s"Prioritized proxies as: $sortedProxies")

          sortedProxies.headOption
        })
        .flatMap(server => Option(server.address))
        .map(_.asInstanceOf[InetSocketAddress]) // because Java
        .map(uriToProxyServer(_))
        .orNull // because Java x2
    }

  private def uriToProxyServer(u: InetSocketAddress): ProxyServer =
    (new ProxyServer.Builder(u.getHostName, u.getPort)).build
  }
}