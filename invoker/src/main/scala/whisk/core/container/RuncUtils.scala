/*
 * Copyright 2015-2016 IBM Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package whisk.core.container

import akka.event.Logging.ErrorLevel

import whisk.common.{ Logging, SimpleExec, TransactionId, LoggingMarkers, PrintStreamEmitter }

object RuncUtils extends Logging {

    private implicit val emitter: PrintStreamEmitter = this

    def list()(implicit transid: TransactionId): String = {
        runRuncCmd(false, Seq("list"))
    }

    /**
     * Synchronously runs the given runc command returning stdout if successful.
     */
    def runRuncCmd(skipLogError: Boolean, args: Seq[String])(implicit transid: TransactionId): String = {
        val start = transid.started(this, LoggingMarkers.INVOKER_DOCKER_CMD("runc_" + args(0)))
        try {
            val fullCmd = getRuncCmd() ++ args

            val (stdout, stderr, exitCode) = SimpleExec.syncRunCmd(fullCmd)

            if (exitCode == 0) {
                transid.finished(this, start)
                stdout.trim
            } else {
                if (!skipLogError) {
                    transid.failed(this, start, s"stdout:\n$stdout\nstderr:\n$stderr", ErrorLevel)
                } else {
                    transid.failed(this, start)
                }
                "error"
            }
        } catch {
            case t: Throwable =>
                transid.failed(this, start, "error: " + t.getMessage, ErrorLevel)
                "error"
        }
    }

    /*
     *  Any global flags are added here.
     */
    private def getRuncCmd(): Seq[String] = {
        val runcBin = "/usr/bin/docker-runc"
        Seq(runcBin)
    }


}
