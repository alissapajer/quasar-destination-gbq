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

import argonaut._ , Argonaut._

final case class GBQDestinationTable(project: String, dataset: String, table: String)
  
final case class  WriteDisposition(value: String)
final case class GBQSchema(typ: String, name: String)

final case class GBQJobConfig(
  sourceFormat: String,
  skipLeadingRows: String,
  allowQuotedNewLines: String,
  schema: List[GBQSchema], 
  timePartition: Option[String],
  writeDisposition: WriteDisposition,
  destinationTable: GBQDestinationTable)

object GBQJobConfig {

  implicit val GBQJobConfigDecodeJson: DecodeJson[GBQJobConfig] =
    DecodeJson(c => {
      val load = c --\ "configuration" --\ "load"
      for {
        sourceFormat <- (load --\ ("sourceFormat")).as[String]
        skipLeadingRows <- (load --\ "skipLeadingRows").as[String]
        allowQuotedNewLines <- (load --\ "allowQuotedNewLines").as[String]
        schema <- (load --\ "schema" --\ "fields").as[List[GBQSchema]]
        timePartition <- (load --\ "timePartition").as[Option[String]]
        writeDisposition <- (load --\ "writeDisposition").as(writeDispositionDecodeJson)
        destinationTable <- (load --\ "destinationTable").as[GBQDestinationTable]
      } yield GBQJobConfig(
          sourceFormat,
          skipLeadingRows,
          allowQuotedNewLines,
          schema,
          timePartition,
          writeDisposition,
          destinationTable)
    })
  
  implicit val GBQJobConfigEncodeJson: EncodeJson[GBQJobConfig] =
    EncodeJson(cfg => Json.obj(
      "configuration" := Json.obj(
        "load" := Json.obj(
          "sourceFormat" := cfg.sourceFormat,
          "skipLeadingRows" := cfg.skipLeadingRows,
          "allowQuotedNewLines" := cfg.allowQuotedNewLines,
          "schema" := Json.obj(
            "fields" := cfg.schema.toList
          ),
          "timePartition" := cfg.timePartition,
          "writeDisposition" := cfg.writeDisposition,
          "destinationTable" := cfg.destinationTable
        )
      )
    ))

  implicit val schemaDecodeJson: DecodeJson[GBQSchema] =
    DecodeJson(c => {
      for {
        typ <- (c --\ "type").as[String]
        name <- (c --\ "name").as[String]
      } yield GBQSchema(typ, name)
    })

  implicit val schemaEncodeJson: EncodeJson[GBQSchema] =
    EncodeJson(schema => Json.obj(
      "type" := schema.typ,
      "name" := schema.name
    ))

  implicit val writeDispositionDecodeJson: DecodeJson[WriteDisposition] = 
    DecodeJson {
      c => c.as[String].flatMap {
        case wp @ "WRITE_APPEND" => DecodeResult.ok(WriteDisposition(wp))
        case wt @ "WRITE_TRUNCATE" => DecodeResult.ok(WriteDisposition(wt))
        case we @ "WRITE_EMPTY" => DecodeResult.ok(WriteDisposition(we))
        case other => DecodeResult.fail("Unrecognized Write Disposition: " + other, c.history)
      }
    }

  implicit val writeDispositionEncodeJson: EncodeJson[WriteDisposition] =
    EncodeJson(wd => wd match {
      case WriteDisposition(value) => jString(value)
    })

  implicit val GBQDestinationTableDecodeJson: DecodeJson[GBQDestinationTable] =
    DecodeJson(c => for {
      projectId <- (c --\ "projectId").as[String]
      datasetId <- (c --\ "datasetId").as[String]
      tableId <- (c --\ "tableId").as[String] 
    } yield GBQDestinationTable(projectId, datasetId, tableId))

  implicit val GBQDestinationTableEncodeJson: EncodeJson[GBQDestinationTable] =
    EncodeJson(dt => Json.obj(
      "projectId" := dt.project,
      "datasetId" := dt.dataset,
      "tableId" := dt.table
    ))
}