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

import quasar.api.destination.{Destination, DestinationError, DestinationType, ResultSink}
import quasar.api.destination.DestinationError.InitializationError
import quasar.connector.{MonadResourceErr, ResourceError}
import quasar.api.push.RenderConfig
import quasar.api.resource.ResourceName
import quasar.api.table.{ColumnType, TableColumn}

import argonaut._, Argonaut._

import cats.ApplicativeError
import cats.effect.{Concurrent, ContextShift, Resource, Sync}
import cats.implicits._

import eu.timepit.refined.auto._

import fs2.Stream

import org.http4s.{
  AuthScheme,
  Credentials,
  EntityEncoder,
  MediaType,
  Method,
  Request,
  Status,
  Uri
}
import org.http4s.argonaut.jsonEncoderOf
import org.http4s.client.Client
import org.http4s.headers.{Authorization, `Content-Type`, Location}

import org.slf4s.Logging

import scalaz.NonEmptyList

import shims._

final class GBQDestination[F[_]: Concurrent: ContextShift: MonadResourceErr](
    client: Client[F], 
    config: GBQConfig,
    sanitizedConfig: Json) extends Destination[F] with Logging {

  def destinationType: DestinationType = DestinationType("gbq", 1L)

  def sinks: NonEmptyList[ResultSink[F]] = NonEmptyList(gbqSink)

  private def gbqSink: ResultSink[F] = 
    ResultSink.csv[F](RenderConfig.Csv()) { (path, columns, bytes) =>
      val gbqSchema = tblColumnToGBQSchema(columns)
      
      val tableNameF = path.uncons match {
        case Some((ResourceName(name), _)) => name.pure[F]
        case _ => MonadResourceErr[F].raiseError[String](
          ResourceError.notAResource(path))
      }

      for {
        tableName <- Stream.eval[F, String](tableNameF)
        gbqJobConfig = formGBQJobConfig(gbqSchema, config, tableName)
        accessToken <- Stream.eval(GBQAccessToken.token(config.authCfg.getBytes("UTF-8")))
        _ <- Stream.eval((mkDataset(client, accessToken.getTokenValue, config)))
        eitherloc <- Stream.eval(mkGbqJob(client, accessToken.getTokenValue, gbqJobConfig))
        _ <- Stream.eval(
          Sync[F].delay(
            log.info(s"(re)creating ${config.project}.${config.datasetId}.${tableName} with schema ${columns.show}")))
        _ <- eitherloc match {
            case Right(locationUri) => {
              upload(client, bytes, locationUri, accessToken.getTokenValue)
            }
            case Left(e) =>
              Stream.eval(Sync[F].delay(ApplicativeError[F, Throwable].raiseError(
                new RuntimeException(s"No Location URL from returned from job: $e"))))
          }
      } yield ()
  }

  // NB: config overwrites when re-pushing tables
  // see schemaUpdateOptions section at
  // https://cloud.google.com/bigquery/docs/reference/rest/v2/Job
  private def formGBQJobConfig(
      schema: List[GBQSchema],
      config: GBQConfig,
      tableId: String): GBQJobConfig =
    GBQJobConfig(
      "CSV",
      "1",
      "true",
      schema,
      Some("DAY"),
      WriteDisposition("WRITE_TRUNCATE"),
      GBQDestinationTable(config.project, config.datasetId, tableId))

  private def tblColumnToGBQSchema(cols: List[TableColumn]): List[GBQSchema] =
    cols map { col => col match {
      case TableColumn(name, tpe) => tpe match {
        case ColumnType.String => GBQSchema("STRING", name)
        case ColumnType.Boolean => GBQSchema("BOOL", name)
        case ColumnType.Number => GBQSchema("NUMERIC", name)
        case ColumnType.LocalDate => GBQSchema("DATE", name)
        case ColumnType.LocalDateTime => GBQSchema("DATETIME", name)
        case ColumnType.LocalTime => GBQSchema("TIME", name)
        case ColumnType.OffsetTime => GBQSchema("TIMESTAMP", name)
        case ColumnType.OffsetDateTime => GBQSchema("TIMESTAMP", name)
        case ColumnType.OffsetDate => GBQSchema("TIMESTAMP", name)
        case ColumnType.Interval => ???
        case ColumnType.Null => ???
      }
    }
  }

  private def mkDataset(
      client: Client[F],
      accessToken: String,
      config: GBQConfig)
      : F[Either[InitializationError[Json], Unit]] = {
    implicit def jobConfigEntityEncoder: EntityEncoder[F, GBQDatasetConfig] = jsonEncoderOf[F, GBQDatasetConfig]

    val dCfg = GBQDatasetConfig(config.project, config.datasetId)
    val bearerToken = Authorization(Credentials.Token(AuthScheme.Bearer, accessToken))
    val datasetReq = Request[F](
      method = Method.POST,
      uri = Uri.fromString(s"https://bigquery.googleapis.com/bigquery/v2/projects/${config.project}/datasets").getOrElse(Uri()))
        .withHeaders(bearerToken)
        .withContentType(`Content-Type`(MediaType.application.json))
        .withEntity(dCfg)

      client.fetch(datasetReq) { resp =>
        resp.status match {
          case Status.Ok | Status.Conflict =>
            ().asRight[InitializationError[Json]].pure[F]
          case status =>
            DestinationError.malformedConfiguration(
              (destinationType, jString("Reason: " + status.reason), 
              sanitizedConfig.toString)).asLeft.pure[F]
        }
      }
    }

  private def mkGbqJob(
      client: Client[F],
      accessToken: String,
      jCfg: GBQJobConfig): F[Either[InitializationError[Json], Uri]] = {

    implicit def jobConfigEntityEncoder: EntityEncoder[F, GBQJobConfig] = jsonEncoderOf[F, GBQJobConfig]

    val authToken = Authorization(Credentials.Token(AuthScheme.Bearer, accessToken))
    val jobReq = Request[F](
      method = Method.POST,
      uri = Uri.fromString(s"https://bigquery.googleapis.com/upload/bigquery/v2/projects/${jCfg.destinationTable.project}/jobs?uploadType=resumable").getOrElse(Uri()))
        .withHeaders(authToken)
        .withContentType(`Content-Type`(MediaType.application.json))
        .withEntity(jCfg)

    client.fetch(jobReq) { resp =>
      resp.status match {
        case Status.Ok => resp.headers match {
          case Location(loc) =>
            loc.uri.asRight.pure[F]
        }
        case _ =>
          DestinationError.malformedConfiguration(
            (destinationType, jString("Reason: " + resp.status.reason), 
            sanitizedConfig.toString)).asLeft.pure[F]
      }
    }
  }

  private def upload(client: Client[F], bytes: Stream[F, Byte], uploadLocation: Uri, accessToken: String): Stream[F, Unit] = {
    val bearerToken = Authorization(Credentials.Token(AuthScheme.Bearer, accessToken))
    val destReq = Request[F](method = Method.POST, uri = uploadLocation)
        .withHeaders(bearerToken)
        .withContentType(`Content-Type`(MediaType.application.`octet-stream`))
        .withEntity(bytes)

    val doUpload = client.fetch(destReq) { resp =>
      resp.status match {
        case Status.Ok => ().pure[F]
        case _ => ApplicativeError[F, Throwable].raiseError[Unit](
            new RuntimeException(s"Upload failed: ${resp.status.reason}" ))
      }
    }
    Stream.eval(doUpload)
  }
}

object GBQDestination {
  def apply[F[_]: Concurrent: ContextShift: MonadResourceErr, C](client: Client[F], config: GBQConfig, sanitizedConfig: Json)
      : Resource[F, Either[InitializationError[C], Destination[F]]] = {
    val x: Either[InitializationError[C], Destination[F]] = new GBQDestination[F](client, config, sanitizedConfig).asRight[InitializationError[C]]
    Resource.liftF(x.pure[F])
  }
}