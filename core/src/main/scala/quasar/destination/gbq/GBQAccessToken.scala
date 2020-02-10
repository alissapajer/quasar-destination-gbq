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

import slamdata.Predef.{Array, Byte, String, println}

import quasar.concurrent.NamedDaemonThreadFactory

import com.google.auth.oauth2.{AccessToken, GoogleCredentials}

import cats.effect._

import java.lang.System
import java.util.Date
import java.io.ByteArrayInputStream
import java.util.concurrent.Executors
import java.security.interfaces.RSAPrivateKey

import com.auth0.jwt._
import com.auth0.jwt.algorithms.Algorithm

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential

import cats.effect.{Blocker, Sync}
import cats.implicits._

import scala.concurrent.ExecutionContext

object GBQAccessToken {
  //TODO: should this return F[AccessToken]
  // or is token() below returning F[AccessToken] enough
  private def genAccessToken[F[_]: Sync](auth: Array[Byte]): F[AccessToken] = Sync[F] delay {
    val authInputStream = new ByteArrayInputStream(auth) 
    val credentials = GoogleCredentials
      .fromStream(authInputStream)
      .createScoped("https://www.googleapis.com/auth/bigquery")
    //credentials.refreshAccessToken

    val x = credentials.refreshAccessToken()
    //println("refreshAccessToken: " + x)

    //val y  = GoogleCredentials.create(x)
    //val z = y.getAccessToken()
    //println("getAccessToken: " + z)
    x
  }

  def scopedCredentials(auth: Array[Byte]) = {
    val authInputStream = new ByteArrayInputStream(auth) 
    GoogleCredential
      .fromStream(authInputStream)
      .createScoped(java.util.Collections.singleton[String]("https://www.googleapis.com/auth/bigquery"))
  }

  // private def gen(auth: Array[Byte]) = {
  //   val credential: GoogleCredential = GoogleCredential.fromStream(auth)
  //   val privateKey: PrivateKey = credential.getServiceAccountPrivateKey
  //   val privateKeyId = credential.getServiceAccountPrivateKeyId
  //   privateKeyId
  // }

  def getAccessToken2[F[_]: Sync](auth: Array[Byte]): F[String] = {
    for {
      now <- Sync[F].delay(System.currentTimeMillis)
    } yield {
      val authInputStream = new ByteArrayInputStream(auth)
      val credential = GoogleCredential.fromStream(authInputStream)
      val privateKey = credential.getServiceAccountPrivateKey.asInstanceOf[RSAPrivateKey]
      val privateKeyId = credential.getServiceAccountPrivateKeyId
      val algorithm: Algorithm = Algorithm.RSA256(null, privateKey)
      val signedJwt: String = JWT.create
          .withIssuedAt(new Date(now))
          .withExpiresAt(new Date(now + 3600 * 1000L))
          .withKeyId(privateKeyId)
          .withIssuer("slamdata-bot-service-account@travis-ci-reform-test-proj.iam.gserviceaccount.com")
          .withSubject("slamdata-bot-service-account@travis-ci-reform-test-proj.iam.gserviceaccount.com")
          .withAudience("https://www.googleapis.com/auth/bigquery")
          .withClaim("email", "slamdata-bot-service-account@travis-ci-reform-test-proj.iam.gserviceaccount.com")
          .sign(algorithm)
      println("signedJwt: " + signedJwt)
      signedJwt
    }
  }



  private val blocker: Blocker =
    Blocker.liftExecutionContext(
      ExecutionContext.fromExecutor(
        Executors.newCachedThreadPool(NamedDaemonThreadFactory("gbq-destination"))))

  def token[F[_]: Sync: ContextShift](auth: Array[Byte]): F[AccessToken] = blocker.blockOn[F, AccessToken](genAccessToken[F](auth))
}