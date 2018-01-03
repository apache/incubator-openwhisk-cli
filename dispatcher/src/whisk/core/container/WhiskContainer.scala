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

import java.time.Clock
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger

import spray.json.JsObject
import spray.json.JsString
import whisk.common.HttpUtils
import whisk.common.TransactionId
import whisk.core.entity.ActionLimits

/**
 * Reifies a whisk container - one that respects the whisk container API.
 */
class WhiskContainer(
    pool: ContainerPool,
    key: String,
    containerName: String,
    image: String,
    network: String,
    pull: Boolean,
    env: Map[String, String],
    boundParams: JsObject,
    limits: ActionLimits,
    args: Array[String] = Array())(implicit transid: TransactionId)
    extends Container(pool, key, Some(containerName), image, network, pull, limits, env, args) {

    var lastLogSize = 0L
    val initTimeoutMilli = 60000

    /*
     * Start time, End time, response from container consisting of status code and payload
     */
    type RunResult = (Instant, Instant, Option[(Int, String)])

    /**
     * This will change as we start doing registry stuff.
     */
    def isBlackbox = !image.startsWith("whisk/")

    /**
     * Merges previously bound parameters with arguments form payload.
     */
    def mergeParams(payload: JsObject, recurse: Boolean = true)(implicit transid: TransactionId): JsObject = {
        info(this, s"merging parameters")
        //debug(this, s"merging ${boundParams.compactPrint} with ${payload.compactPrint}")
        JsObject(boundParams.fields ++ payload.fields)
    }


    /**
     * Send initialization payload to container.
     */
    def init(args: JsObject)(implicit transid: TransactionId): RunResult = {
        val start = ContainerCounter.now()
        if (isBlackbox) Thread.sleep(3000)  // this shouldn't be needed but leave it for now
        info(this, s"sending initialization to ${this.details}")
        val result = sendPayload("/init", JsObject("value" -> args), initTimeoutMilli)   // This will retry.
        val end = ContainerCounter.now()
        info(this, s"initialization result: ${result}")
        (start, end, result)
    }

    /**
     * Sends a run command to action container to run once.
     *
     * @param state the value of the status to compare the actual state against
     * @return triple of start time, end time, response for user action.
     */
    def run(args: JsObject, meta: JsObject, timeout: Int)(implicit transid: TransactionId): RunResult = {
        val start = ContainerCounter.now()
        val response = sendPayload("/run", JsObject(meta.fields + ("value" -> args)), timeout)
        (start, ContainerCounter.now(), response)
    }

    /**
     * An alternative entry point for direct testing of action container.
     */
    def run(payload: String, activationId: String): RunResult = {
        val params = JsObject("payload" -> JsString(payload))
        val meta = JsObject("activationId" -> JsString(activationId))
        run(params, meta, 30000)(TransactionId.dontcare)
    }

    /**
     * Tear down the container and retrieve the logs.
     */
    def teardown()(implicit transid: TransactionId): String = {
        getContainerLogs(Some(containerName)).getOrElse("none")
    }

    /**
     * Gets the current size of the mounted file associated with this whisk container.
     */
    def getLogSize(mounted: Boolean) = pool.getLogSize(this, mounted)

    /**
     * Gets docker logs
     */
    def getDockerLogContent(start: Long, end: Long, mounted: Boolean)(implicit transid: TransactionId): Array[Byte] = {
        this.synchronized {
            containerId map { id => pool.getDockerLogContent(id, start, end, mounted) } getOrElse Array()
        }
    }

    /**
     * Posts a message to the container.
     *
     * @param msg the message to post
     * @return response from container if any as array of byte
     */
    private def sendPayload(endpoint: String, msg: JsObject, timeout: Int = 30000): Option[(Int, String)] = {
        containerIP map { host =>
            val http = new HttpUtils(host)
            val (code, bytes) = http.dopost(endpoint, msg, Map(), timeout)
            Some(code, new String(bytes, "UTF-8"))
        } getOrElse None
    }

}

/**
 * Singleton to thread-safely count containers.
 */
protected[container] object ContainerCounter {
    private val cnt = new AtomicInteger(0)
    private def next(): Int = {
        cnt.incrementAndGet()
    }
    private def cut(): Int = {
        cnt.get()
    }

    def now() = Instant.now(Clock.systemUTC())

    def containerName(containerPrefix: String, containerSuffix: String): String = {
        s"wsk${containerPrefix}_${ContainerCounter.next()}_${containerSuffix}_${now()}".replaceAll("[^a-zA-Z0-9_]", "")
    }
}
