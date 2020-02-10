import scala.collection.Seq

homepage in ThisBuild := Some(url("https://github.com/slamdata/quasar-destination-gbq"))

scmInfo in ThisBuild := Some(ScmInfo(
  url("https://github.com/slamdata/quasar-destination-gbq"),
  "scm:git@github.com:slamdata/quasar-destination-gbq.git"))

val ArgonautVersion = "6.2.3"
val Http4sVersion = "0.20.10"
val SpecsVersion = "4.7.0"
val Slf4s = "1.7.25"

// Include to also publish a project's tests
lazy val publishTestsSettings = Seq(
  publishArtifact in (Test, packageBin) := true)

lazy val QuasarVersion = IO.read(file("./quasar-version")).trim

lazy val root = project
  .in(file("."))
  .settings(noPublishSettings)
  .aggregate(core)
  .enablePlugins(AutomateHeaderPlugin)

lazy val core = project
  .in(file("core"))
  .settings(name := "quasar-destination-gbq")
  .settings(
    performMavenCentralSync := false,

    quasarPluginName := "gbq",
    quasarPluginQuasarVersion := QuasarVersion,
    quasarPluginDestinationFqcn := Some("quasar.destination.gbq.GBQDestinationModule$"),

    quasarPluginDependencies ++= Seq(
      "com.google.auth" % "google-auth-library-oauth2-http" % "0.18.0",
      "com.google.api-client" % "google-api-client" % "1.30.7",
      "org.slf4s" %% "slf4s-api" % Slf4s,
      "org.http4s" %% "http4s-argonaut" % Http4sVersion,
      "org.http4s" %% "http4s-async-http-client" % Http4sVersion,
      "io.argonaut" %% "argonaut" % ArgonautVersion),

    libraryDependencies ++= Seq(
      "com.github.tototoshi" %% "scala-csv" % "1.3.6" % Test,
      "org.specs2" %% "specs2-core" % SpecsVersion % Test,
      "com.slamdata" %% "quasar-foundation" % QuasarVersion,
      "com.auth0" % "java-jwt" % "3.9.0",
      "com.slamdata" %% "quasar-foundation" % QuasarVersion % Test classifier "tests",
      "org.specs2" %% "specs2-scalacheck" % SpecsVersion % Test,
      "org.specs2" %% "specs2-scalaz" % SpecsVersion % Test),

    publishAsOSSProject := true)
  .enablePlugins(AutomateHeaderPlugin, QuasarPlugin)
