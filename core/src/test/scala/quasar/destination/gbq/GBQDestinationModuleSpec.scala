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

import quasar.EffectfulQSpec
import quasar.api.destination.{Destination, DestinationType, DestinationError}
import quasar.api.destination.DestinationError.InitializationError
import quasar.connector.ResourceError
import quasar.contrib.scalaz.MonadError_

import argonaut._, Argonaut._

import cats.effect.{IO, Timer, ContextShift}

import eu.timepit.refined.auto._

import java.nio.file.{Files, Paths}
import java.nio.charset.StandardCharsets.UTF_8

import scala.concurrent.ExecutionContext.Implicits.global

object GBQDestinationModuleSpec extends EffectfulQSpec[IO] {
  val authCfgPath = Paths.get(getClass.getClassLoader.getResource("gbqAuthFile.json").toURI)
  val authCfgString: String = new String(Files.readAllBytes(authCfgPath), UTF_8)

  "initialization" should {
      "fail with malformed config when config is not decodable" >>* {
        val cfg = Json("malformed" := true)
        dest(cfg)(r => IO { r match {
          case Left(DestinationError.MalformedConfiguration(_, c, _)) =>
            c must_=== jString(GBQDestinationModule.Redacted)
          case _ => ko("Expected a malformed configuration")
        }})
    }

    "fail with Not Found when checking for non existing project" >>* {
      val cfg = config(authCfg = Some(authCfgString), Some("bogusproject"), Some("mydataset"))
      dest(cfg)(r => IO { r match {
        case Left(DestinationError.InvalidConfiguration(_, c, _) ) =>
          c must_=== jString("Not Found")
        case _ => ko("Expected a 404 failed request")
      }})
    }

    "successfully check real project exists" >>* {
      val cfg = config(authCfg = Some(authCfgString), Some("travis-ci-reform-test-proj"), Some("mydataset"))
      dest(cfg)(r => IO { r match {
        case Right(a) => a.destinationType must_=== DestinationType("gbq", 1L)
        case _ => ko("Failed to correctly create Destination")
      }})
    }
  }

  implicit val CS: ContextShift[IO] = IO.contextShift(global)
  implicit val TM: Timer[IO] = IO.timer(global)
  implicit val MRE: MonadError_[IO, ResourceError] = MonadError_.facet[IO](ResourceError.throwableP)

  def config(authCfg: Option[String] = None, project: Option[String] = None, datasetId: Option[String] = None): Json =
    ("authCfg" := authCfg) ->:
    ("project" := project) ->:
    ("datasetId" := datasetId) ->:
    jEmptyObject

  def dest[A](cfg: Json)(f: Either[InitializationError[Json], Destination[IO]] => IO[A]): IO[A] =
    GBQDestinationModule.destination[IO](cfg).use(f)
}