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

import quasar.api.destination.DestinationError.InitializationError
import quasar.api.destination.{Destination, ResultSink}
import quasar.api.table.{ColumnType, TableColumn}
import quasar.api.resource.{ResourceName, ResourcePath}
import quasar.api.destination.{Destination, DestinationError, DestinationType}
import quasar.connector.ResourceError
import quasar.contrib.proxy.Search
import quasar.contrib.scalaz.MonadError_

import quasar.EffectfulQSpec

import argonaut._, Argonaut._

import cats.effect.{ConcurrentEffect, IO, Resource, Timer}
import cats.implicits._
import scala.concurrent.duration._

import eu.timepit.refined.auto._

import fs2.{Stream, text}

import java.nio.file.{Files, Paths}
import java.nio.charset.StandardCharsets.UTF_8

import org.http4s.argonaut.jsonEncoderOf
import org.http4s.client.asynchttpclient.AsyncHttpClient
import org.http4s.client.Client
import org.http4s.{
  AuthScheme, 
  Credentials, 
  EntityEncoder, 
  MediaType,
  Method, 
  Request, 
  Status,
  Uri}
import org.http4s.headers.Authorization
import org.http4s.headers.`Content-Type`

import scala.concurrent.ExecutionContext
import scala.concurrent.ExecutionContext.Implicits.global

import scala.util.Right
import scalaz.{-\/,\/-}

import shims._

object GBQDestinationSpec extends EffectfulQSpec[IO] {
  sequential

  implicit val timer: Timer[IO] = IO.timer(ExecutionContext.global)

  val testProject = "travis-ci-reform-test-proj"
  val testDataset = "testdataset" //TODO: make arbitrary dataset names
  val authCfgPath = Paths.get(getClass.getClassLoader.getResource("gbqAuthFile.json").toURI)
  val authCfgString: String = new String(Files.readAllBytes(authCfgPath), UTF_8)
  val cfg = config(authCfg = Some(authCfgString), Some(testProject), Some(testDataset))
  val resource = mkClient[IO]

  "csv link" should {
    "reject empty paths with NotAResource" >>* {
      csv(cfg) { sink =>
        val p = ResourcePath.root()
        val r = sink.run(p, List(TableColumn("a", ColumnType.Boolean)), Stream.empty).compile.drain

        MRE.attempt(r).map(_ must beLike {
          case -\/(ResourceError.NotAResource(p2)) => p2 must_=== p
        })
      }
    }

    "successfully upload table" >>* {
      val dst = ResourcePath.root() / ResourceName("foo") / ResourceName("bar.csv")
      val data = Stream("col1,col2\r\nstuff,true\r\n").through(text.utf8Encode)

      csv(cfg) { sink =>
          val r = sink.run(dst, List(TableColumn("a", ColumnType.String), TableColumn("b", ColumnType.Boolean)), data).compile.drain
          //TODO: give BigQuery to make it aware of newly pushed table, is there something else we can do?
          Timer[IO].sleep(3.seconds).flatMap { _ =>
            MRE.attempt(r).map(_ must beLike {
              case \/-(value) => value must_===(())
            })
          }
      }
    }

    "successfully check dataset was created" >>* {
      for {
        accessToken <- GBQAccessToken.token[IO](authCfgString.getBytes("UTF-8"))
        auth = Authorization(Credentials.Token(AuthScheme.Bearer, accessToken.getTokenValue))
        req = mkGeneralRequest[String](
          auth, 
          "",
          s"https://content-bigquery.googleapis.com/bigquery/v2/projects/${testProject}/datasets",
          Method.GET,
          `Content-Type`(MediaType.application.json)) 
        resp <- resource.use(client => mkRequest(client, req))
        containsDatasets <- resp match {
          case Right(value) =>
            value.body.compile.toVector.map(v => {
              val t = v.map(_.toChar).mkString
              t.contains(testDataset)
            })
          case Left(value) => IO { false }
        }
        back <- IO {
          containsDatasets must beTrue
           false must beFalse
        }
      } yield back
    }

    "successfully check uploaded table exists" >>* {
      for {
        accessToken <- GBQAccessToken.token[IO](authCfgString.getBytes("UTF-8"))
        auth = Authorization(Credentials.Token(AuthScheme.Bearer, accessToken.getTokenValue))
        req = mkGeneralRequest[String](
          auth, 
          "",
          s"https://content-bigquery.googleapis.com/bigquery/v2/projects/${testProject}/datasets/${testDataset}/tables",
          Method.GET,
          `Content-Type`(MediaType.application.json))
        resp <- resource.use(client => {
          Timer[IO].sleep(3.seconds).flatMap { _ =>
            mkRequest(client, req)
          }
          
        })
        containsTableName <- resp match {
          case Right(value) =>
            value.body.compile.toVector.map(v => {
              val t = v.map(_.toChar).mkString
              t.contains("foo")
            })
          case Left(value) => IO { false }
        }
      } yield {
        containsTableName must beTrue
      }
    }

    "successfully check table contents" >>* {
      for {
        accessToken <- GBQAccessToken.token[IO](authCfgString.getBytes("UTF-8"))
        auth = Authorization(Credentials.Token(AuthScheme.Bearer, accessToken.getTokenValue))
        req = mkGeneralRequest[String](
          auth,
          "",
          s"https://bigquery.googleapis.com/bigquery/v2/projects/${testProject}/datasets/${testDataset}/tables/foo/data",
          Method.GET,
          `Content-Type`(MediaType.application.json))
        resp <- resource.use(client => mkRequest(client, req))
        tableContentisCorrect <- resp match {
          case Right(value) =>
            value.body.compile.toVector.map(v => {
              val t = v.map(_.toChar).mkString
              t.contains("stuff")
            })
          case Left(value) => IO { false }
        }
      } yield {
        tableContentisCorrect must beTrue
      }
    }

    "successfully cleanup dataset and tables" >>* {
      for {
        accessToken <- GBQAccessToken.token[IO](authCfgString.getBytes("UTF-8"))
        auth = Authorization(Credentials.Token(AuthScheme.Bearer, accessToken.getTokenValue))
        req = mkGeneralRequest[String](
          auth, 
          "",
          s"https://bigquery.googleapis.com/bigquery/v2/projects/${testProject}/datasets/${testDataset}?deleteContents=true",
          Method.DELETE,
          `Content-Type`(MediaType.application.json))
        resp <- resource.use(client => mkRequest(client, req))
        back <- IO {
          resp must beLike {
            case Right(_) => ok
          }
        }
      } yield back
    }
  }

  val DM = GBQDestinationModule

  implicit val MRE: MonadError_[IO, ResourceError] =
    MonadError_.facet[IO](ResourceError.throwableP)

  def csv[A](cfg: Json)(f: ResultSink.Csv[IO] => IO[A]): IO[A] =
    dest(cfg) {
      case Left(err) =>
        IO.raiseError(new RuntimeException(err.toString))

      case Right(dst) =>
        dst.sinks.list
          .collectFirst({ case c @ ResultSink.Csv(_, _) => c })
          .map(f)
          .getOrElse(IO.raiseError(new RuntimeException("No CSV sink found!")))
    }

  def dest[A](cfg: Json)(f: Either[InitializationError[Json], Destination[IO]] => IO[A]): IO[A] =
    GBQDestinationModule.destination[IO](cfg).use(f)

  def config(authCfg: Option[String] = None, project: Option[String] = None, datasetId: Option[String] = None): Json =
    ("authCfg" := authCfg) ->:
    ("project" := project) ->:
    ("datasetId" := datasetId) ->:
    jEmptyObject

  implicit def jobConfigEntityEncoder: EntityEncoder[IO, GBQJobConfig] = jsonEncoderOf[IO, GBQJobConfig]
  def mkGeneralRequest[A](
      bearerToken: Authorization,
      data: A,
      url: String,
      reqMethod: Method,
      contentType: `Content-Type`)(implicit a: EntityEncoder[IO,A]): Request[IO] = {
    Request[IO](
      method = reqMethod,
      uri = Uri.fromString(url).getOrElse(Uri()))
        .withHeaders(bearerToken)
        .withContentType(contentType)
        .withEntity(data)
  }

  def mkClient[F[_]: ConcurrentEffect]: Resource[F, Client[F]] = {
      Resource.liftF(Search[F]).flatMap(selector =>
        AsyncHttpClient.resource())
    }

  def mkRequest(client: Client[IO], req: Request[IO]) = {
    client.fetch(req) { resp =>
      resp.status match {
        case Status(_) => resp.asRight.pure[IO]
        case _ =>
          DestinationError.malformedConfiguration(
            (DestinationType("gbq", 1L) , jString("Reason: " + resp.status.reason), 
            "Response Code: " + resp.status.code)).asLeft.pure[IO]
      }
    }
  }

}