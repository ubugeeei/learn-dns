ThisBuild / scalaVersion := "3.7.3"
ThisBuild / organization := "dev.ubugeeei"
ThisBuild / version := "0.1.0-SNAPSHOT"

lazy val root = project.in(file(".")).settings(
  name := "learn-dns",
  scalacOptions ++= Seq(
    "-deprecation",
    "-feature",
    "-unchecked",
    "-Wunused:all",
    "-Wvalue-discard",
    "-Wnonunit-statement"
  ),
  libraryDependencies += "org.scalameta" %% "munit" % "1.2.0" % Test,
  Test / parallelExecution := true
)
