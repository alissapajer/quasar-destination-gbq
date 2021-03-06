/*
 * Copyright 2020 Precog Data
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

import slamdata.Predef.RuntimeException

import scala.Predef.String

import quasar.api.{Column, ColumnType}
import quasar.api.destination.DestinationError.InitializationError
import quasar.connector.destination.{Destination, PushmiPullyu, ResultSink}
import quasar.api.resource.{ResourceName, ResourcePath}
import quasar.connector.ResourceError
import quasar.contrib.scalaz.MonadError_
import quasar.EffectfulQSpec

import argonaut._, Argonaut._

import cats.data.NonEmptyList
import cats.effect.{Blocker, IO, Timer}

import fs2.{Pipe, Stream, text}

import org.http4s.client.Client
import org.http4s.{
  AuthScheme,
  Credentials,
  Method,
  Request,
  Status,
  Uri
}
import org.http4s.headers.Authorization
import org.http4s.client._


import scala.{Byte, Either, StringContext, Unit}
import scala.concurrent.duration._
import scala.concurrent.ExecutionContext
import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.Right
import scala.util.Left

import scalaz.{-\/,\/-}

import java.nio.file.{Files, Paths}
import java.nio.charset.StandardCharsets.UTF_8
import java.util.concurrent.Executors
import java.util.UUID

import shims._
import shapeless.PolyDefns.identity

object GBQDestinationSpec extends EffectfulQSpec[IO] {
  sequential

  import GBQConfig.serviceAccountConfigCodecJson

  implicit val timer: Timer[IO] = IO.timer(ExecutionContext.global)

  val TEST_PROJECT = "precog-ci-275718"
  val AUTH_FILE = "precog-ci-275718-e913743ebfeb.json"

  val testDataset = "dataset_" + UUID.randomUUID.toString.replace("-", "_").toString
  val tableName = "table_" + UUID.randomUUID.toString.replace("-", "_").toString

  val authCfgPath = Paths.get(getClass.getClassLoader.getResource(AUTH_FILE).toURI)
  val authCfgString = new String(Files.readAllBytes(authCfgPath), UTF_8)
  val authCfgJson: Json = Parse.parse(authCfgString) match {
    case Left(value) => Json.obj("malformed" := true)
    case Right(value) => value
  }

  val gbqConfig = GBQConfig(authCfgJson.as[ServiceAccountConfig].toOption.get, testDataset)
  val gbqCfg = gbqConfig.asJson
  val blockingPool = Executors.newFixedThreadPool(5)
  val blocker = Blocker.liftExecutorService(blockingPool)
  val httpClient: Client[IO] = JavaNetClientBuilder[IO](blocker).create

  "csv link" should {
    "reject empty paths with NotAResource" >>* {
      val path = ResourcePath.root()
      val req = csv(gbqCfg) { consume =>
        consume(path, NonEmptyList.one(Column("a", ColumnType.Boolean)))
          .apply(Stream.empty)
          .compile.drain
      }
      MRE.attempt(req).map(_ must beLike {
        case -\/(ResourceError.NotAResource(p2)) => p2 must_=== path
      })
    }
  }

  "bigquery upload" should {

    "successfully upload table" >>* {
      val data = Stream("col1,col2\r\nstuff,true\r\n").through(text.utf8Encode)
      val path = ResourcePath.root() / ResourceName(tableName) / ResourceName("bar.csv")
      val req =  csv(gbqCfg) { consume =>
        data
          .through(consume(
            path,
            NonEmptyList.of(Column("a", ColumnType.String), Column("b", ColumnType.Boolean))))
          .compile.drain
      }
      Timer[IO].sleep(5.seconds).flatMap { _ =>
        MRE.attempt(req).map(_ must beLike {
          case \/-(value) => value must_===(())
        })
      }
    }

    "successfully check dataset was created" >>* {
      for {
        accessToken <- GBQAccessToken.token[IO](gbqConfig.serviceAccountAuthBytes)
        auth = Authorization(Credentials.Token(AuthScheme.Bearer, accessToken.getTokenValue))
        req = Request[IO](
          method = Method.GET,
          uri = Uri.fromString(s"https://bigquery.googleapis.com/bigquery/v2/projects/${TEST_PROJECT}/datasets")
            .getOrElse(Uri()))
            .withHeaders(auth)
        resp <- Timer[IO].sleep(5.seconds).flatMap { _ =>
          httpClient.run(req).use {
            case Status.Successful(r) => r.attemptAs[String].leftMap(_.message).value
            case r => r.as[String].map(b => Left(s"Request ${req} failed with status ${r.status.code} and body ${b}"))
        }}
        body = resp.fold(identity, identity)
        result <- IO {
           body.contains(testDataset) must beTrue
        }
      } yield result
    }

    "successfully check uploaded table exists" >>* {
      for {
        accessToken <- GBQAccessToken.token[IO](gbqConfig.serviceAccountAuthBytes)
        auth = Authorization(Credentials.Token(AuthScheme.Bearer, accessToken.getTokenValue))
        req = Request[IO](
          method = Method.GET,
          uri = Uri.fromString(s"https://bigquery.googleapis.com/bigquery/v2/projects/${TEST_PROJECT}/datasets/${testDataset}/tables")
            .getOrElse(Uri()))
            .withHeaders(auth)
        resp <- Timer[IO].sleep(5.seconds).flatMap { _ =>
          httpClient.run(req).use {
            case Status.Successful(r) => r.attemptAs[String].leftMap(_.message).value
            case r => r.as[String].map(b => Left(s"Request ${req} failed with status ${r.status.code} and body ${b}"))
        }}
        body = resp.fold(identity, identity)
        result <- IO {
           body.contains(tableName) must beTrue
        }
      } yield result
    }

    "successfully check table contents" >>* {
      for {
        accessToken <- GBQAccessToken.token[IO](gbqConfig.serviceAccountAuthBytes)
        auth = Authorization(Credentials.Token(AuthScheme.Bearer, accessToken.getTokenValue))
        req = Request[IO](
          method = Method.GET,
          uri = Uri.fromString(s"https://bigquery.googleapis.com/bigquery/v2/projects/${TEST_PROJECT}/datasets/${testDataset}/tables/${tableName}/data")
            .getOrElse(Uri()))
            .withHeaders(auth)
        resp <- Timer[IO].sleep(5.seconds).flatMap { _ =>
          httpClient.run(req).use {
            case Status.Successful(r) => r.attemptAs[String].leftMap(_.message).value
            case r => r.as[String].map(b => Left(s"Request ${req} failed with status ${r.status.code} and body ${b}"))
        }}
        body = resp.fold(identity, identity)
        result <- IO {
          body.contains("stuff") must beTrue
        }
      } yield result
    }

    "successfully cleanup dataset and tables" >>* {
      for {
        accessToken <- GBQAccessToken.token[IO](gbqConfig.serviceAccountAuthBytes)
        auth = Authorization(Credentials.Token(AuthScheme.Bearer, accessToken.getTokenValue))
        req = Request[IO](
          method = Method.DELETE,
          uri = Uri.fromString(s"https://bigquery.googleapis.com/bigquery/v2/projects/${TEST_PROJECT}/datasets/${testDataset}?deleteContents=true")
            .getOrElse(Uri()))
            .withHeaders(auth)
        resp <- Timer[IO].sleep(5.seconds).flatMap { _ =>
          httpClient.run(req).use {
            case Status.Successful(r) => IO { r.status }
            case r => IO { r.status }
        }}
        result <- IO {
          resp must beLike {
            case Status.NoContent => ok
          }
        }
      } yield result
    }
  }

  implicit val MRE: MonadError_[IO, ResourceError] =
    MonadError_.facet[IO](ResourceError.throwableP)

    def csv[A](
        gbqcfg: Json)(
          f: ((ResourcePath, NonEmptyList[Column[ColumnType.Scalar]]) => Pipe[IO, Byte, Unit]) => IO[A])
        : IO[A] =
    dest(gbqcfg) {
      case Left(err) =>
        IO.raiseError(new RuntimeException(err.toString))
      case Right(dst) =>
        dst.sinks.toList
          .collectFirst {
            case c @ ResultSink.CreateSink(_) => c
          }
          .map { s =>
            val sink = s.asInstanceOf[ResultSink.CreateSink[IO, ColumnType.Scalar, Byte]]
            f(sink.consume(_, _)._2)
          }
          .getOrElse(IO.raiseError(new RuntimeException("No CSV sink found!")))
    }

  def dest[A](cfg: Json)(f: Either[InitializationError[Json], Destination[IO]] => IO[A]): IO[A] = {
    val pushPull: PushmiPullyu[IO] = _ => _ => Stream.empty[IO]

    GBQDestinationModule.destination[IO](cfg, pushPull).use(f)
  }
}
