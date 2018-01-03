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

package whisk.core.invoker

import java.time.Clock
import java.time.Instant
import scala.collection.concurrent.TrieMap
import scala.concurrent.ExecutionContext
import scala.concurrent.Future
import scala.util.Failure
import scala.util.Success
import scala.util.Try
import scala.util.matching.Regex.Match
import akka.japi.Creator
import spray.json.DefaultJsonProtocol.IntJsonFormat
import spray.json.DefaultJsonProtocol.StringJsonFormat
import spray.json.JsArray
import spray.json.JsObject
import spray.json.JsValue
import spray.json.pimpAny
import spray.json.pimpString
import spray.json._
import whisk.common.ConsulKV
import whisk.common.ConsulKV.InvokerKeys
import whisk.common.ConsulKVReporter
import whisk.common.Counter
import whisk.common.SimpleExec
import whisk.common.TransactionId
import whisk.common.Verbosity
import whisk.core.WhiskConfig
import whisk.core.WhiskConfig.consulServer
import whisk.core.WhiskConfig.dockerRegistry
import whisk.core.WhiskConfig.edgeHost
import whisk.core.WhiskConfig.logsDir
import whisk.core.WhiskConfig.whiskVersion
import whisk.core.connector.Message
import whisk.core.container.ContainerPool
import whisk.core.dispatcher.DispatchRule
import whisk.core.dispatcher.Dispatcher
import whisk.core.entity.ActivationId
import whisk.core.entity.DocId
import whisk.core.entity.DocInfo
import whisk.core.entity.Subject
import whisk.core.entity.WhiskAction
import whisk.core.entity.WhiskActivation
import whisk.core.entity.WhiskActivationStore
import whisk.core.entity.WhiskAuth
import whisk.core.entity.WhiskAuthStore
import whisk.core.entity.WhiskEntity
import whisk.core.entity.WhiskEntityStore
import whisk.http.BasicHttpService
import whisk.core.entity.ActivationResponse
import whisk.core.entity.ActivationLogs
import whisk.core.container.WhiskContainer
import whisk.utils.JsonUtils
import whisk.core.entity.DocRevision
import whisk.core.entity.EntityName
import whisk.core.entity.Namespace

/**
 * A kafka message handler that invokes actions as directed by message on topic "/actions/invoke".
 * The message path must contain a fully qualified action name and an optional revision id.
 *
 * @param config the whisk configuration
 * @param instance the invoker instance number
 * @param executionContext an execution context for futures
 * @param runningInContainer if false, invoker is run outside a container -- for testing
 */
class Invoker(
    config: WhiskConfig,
    instance: Int,
    implicit private val executionContext: ExecutionContext,
    runningInContainer: Boolean = true)
    extends DispatchRule("invoker", "/actions/invoke", s"""(.+)/(.+)/(.+),(.+)/(.+)""") {

    override def setVerbosity(level: Verbosity.Level) = {
        super.setVerbosity(level)
        pool.setVerbosity(level)
        entityStore.setVerbosity(level)
        authStore.setVerbosity(level)
        activationStore.setVerbosity(level)
    }

    /**
     * This is the handler for the kafka message
     *
     * @param msg is the kafka message payload as Json
     * @param matches contains the regex matches
     */
    override def doit(msg: Message, matches: Seq[Match])(implicit transid: TransactionId): Future[DocInfo] = {
        Future {
            // conformance checks can terminate the future if a variance is detected
            require(matches != null && matches.size >= 1, "matches undefined")
            require(matches(0).groupCount >= 3, "wrong number of matches")
            require(matches(0).group(2).nonEmpty, "action namespace undefined") // fully qualified name (namespace:name)
            require(matches(0).group(3).nonEmpty, "action name undefined") // fully qualified name (namespace:name)
            require(msg != null, "message undefined")

            val regex = matches(0)
            val nanespace = Namespace(regex.group(2))
            val name = EntityName(regex.group(3))
            val version = if (regex.groupCount == 4) DocRevision(regex.group(4)) else DocRevision()
            val action = DocId(WhiskEntity.qualifiedName(nanespace, name)).asDocInfo(version)
            action
        } flatMap { fetchFromStoreAndInvoke(_, msg) }
    }

    /**
     * Common point for injection from Kafka or InvokerServer.
     */
    def fetchFromStoreAndInvoke(action: DocInfo, msg: Message)(
        implicit transid: TransactionId): Future[DocInfo] = {
        val subject = msg.subject
        val payload = msg.content getOrElse JsObject()
        info(this, s"${action.id} $subject ${msg.activationId}")

        // caching is enabled since actions have revision id and an updated
        // action will not hit in the cache due to change in the revision id;
        // if the doc revision is missing, then bypass cache
        val actionPromise = WhiskAction.get(entityStore, action, action.rev != DocRevision())
        // bypass cache and fetch from datastore directly since record may be stale
        // due to out of band update
        val authPromise = WhiskAuth.get(authStore, subject, false)

        val activationPostCheck = actionPromise flatMap { theAction =>
            authPromise flatMap { theAuth =>
                invokeAction(theAction, theAuth, payload, msg) map {
                    activationDoc =>
                        info(this, s"recorded activation '$activationDoc'")
                        activationDoc
                }
            }
        }

        actionPromise onFailure { case t => error(this, s"failed to fetch action record ${action.id}: ${t.getMessage}") }
        authPromise onFailure { case t => error(this, s"failed to fetch auth record $subject: ${t.getMessage}") }
        activationPostCheck
    }

    protected def invokeAction(action: WhiskAction, auth: WhiskAuth, payload: JsObject, msg: Message)(
        implicit transid: TransactionId): Future[DocInfo] = {
        activationCounter.next()
        val getStart = Instant.now(Clock.systemUTC())
        pool.getAction(action, auth) match {
            case Some((con, initResultOpt)) => Future {
                val effectiveResult = // The result of init - if it's bad - or the run
                    initResultOpt match {
                        case None | Some((_, _, Some((200, _)))) => { // cached or good init
                            val params = con.mergeParams(payload)
                            info(this, s"sending arguments to ${action.fullyQualifiedName} ${con.details}")
                            val res = con.run(params, msg.meta, action.limits.timeout.millis)
                            info(this, s"finished running activation id: ${msg.activationId}")
                            (false, res)
                        }
                        case _ => (true, initResultOpt.get) // None ruled out
                    }
                // Try a little slack for json log driver to process
                Thread.sleep(if (con.isBlackbox) BlackBoxSlack else RegularSlack)
                effectiveResult
            } flatMap {
                case (delete, (start, end, response)) =>
                    val size = waitForLogs(con)
                    val containerName = con.name
                    val containerIP = con.containerIP.get
                    val containerId = con.containerId.get
                    val rawContents = con.getDockerLogContent(con.lastLogSize, size, runningInContainer)
                    val contents = processJsonDriverLogContents(containerName, con.lastLogSize, size, rawContents)
                    val activation = makeWhiskActivation(msg, action, auth, payload, start, end, response, contents)
                    val counter = incrementUserActivationCounter(auth.subject)
                    con.lastLogSize = size
                    pool.putBack(con, delete)
                    info(this, s"returned container")
                    info(this, s"'${auth.subject}' has '$counter' activations processed")
                    // update the container map before writing back the activation so that
                    // the container name is observable once the activation id is observable
                    putContainerName(activation.activationId, containerName + "@" + containerIP)
                    WhiskActivation.put(activationStore, activation)
            }
            case None => { // this corresponds to the container not even starting - not /init failing
                info(this, s"failed to start or get a container")
                val now = Instant.now(Clock.systemUTC())
                val response = Some(420, "Error starting container")
                val contents = JsArray(JsString("Error starting container"))
                val activation = makeWhiskActivation(msg, action, auth, payload, getStart, now, response, contents)
                WhiskActivation.put(activationStore, activation)
            }
        }
    }

    private val RegularSlack = 100 // millis
    private val BlackBoxSlack = 200 // millis
    private val AdditionalSlack = 200 // millis

    // The nodeJsAction runner inserts this line in the logs at the end
    // of each activation
    private val END_OF_ACTIVATION_MARKER = "XXX_THE_END_OF_A_WHISK_ACTIVATION_XXX"

    /**
     * Waits for log cursor to advance. This will retry up to 'abort' times
     * if the curor has not yet advanced. This will penalize containers that
     * do not log. It is OK for nodejs containers because the runtime emits
     * the END_OF_ACTIVATION_MARKER automatically and that advances the cursor.
     *
     * Splitting the logs from the response of the activation will reduce this
     * delay.
     */
    private def waitForLogs(con: WhiskContainer, abort: Int = 3)(implicit transid: TransactionId): Long = {
        val size = con.getLogSize(runningInContainer)
        if (size == con.lastLogSize && abort > 0) {
            info(this, s"log cursor has not yet advanced, trying $abort more ${if (abort == 1) "time" else "times"}")
            Thread.sleep(AdditionalSlack)
            waitForLogs(con, abort - 1)
        } else size
    }

    /**
     * Checks if msg hold a normal user-generated log message.
     */
    private def containsNormalLogMessage(msg: JsObject): Boolean = {
        msg.fields.get("log") map {
            case JsString(s) => s.trim != END_OF_ACTIVATION_MARKER
            case _           => false
        } getOrElse false
    }

    /**
     * Checks the output of the docker json-file log driver is not truncated (not flushed).
     * It returns a possibly sanitized version of the output.
     */
    private def processJsonDriverLogContents(name: String, start: Long, end: Long, contents: Array[Byte])(implicit transid: TransactionId): JsArray = {
        val logMsgs = new String(contents, "UTF-8")
        info(this, s"!!! $name $start..$end")

        if (logMsgs.nonEmpty) {
            JsArray(logMsgs.split("\n") map { l =>
                Try {
                    // each line should be a JSON object
                    l.parseJson.asJsObject
                }
            } filter {
                case Success(t) =>
                    // drop message if it contains a system marker
                    containsNormalLogMessage(t)
                case Failure(t) =>
                    // drop lines that did not parse to JSON objects
                    error(this, s"log line skipped/did not parse: $t")
                    false
            } map {
                _.get.getFields("time", "stream", "log") match {
                    case Seq(JsString(t), JsString(s), JsString(l)) => f"$t%-30s $s: ${l.trim}".toJson
                }
            } toList)
        } else {
            warn(this, s"log message is empty")
            JsArray()
        }
    }

    private def processResponseContent(response: Option[(Int, String)])(implicit transid: TransactionId): ActivationResponse = {
        response map { pair =>
            val (code, contents) = pair
            debug(this, s"response: '$contents'")
            val json = Try { contents.parseJson.asJsObject }

            json match {
                case Success(result @ JsObject(fields)) =>
                    // The 'error' field of the object, if it exists.
                    val errorOpt = fields.get(ActivationResponse.ERROR_FIELD)

                    if(code == 200) {
                        errorOpt.map { error =>
                            ActivationResponse.applicationError(error)
                        }.getOrElse {
                            // The happy path.
                            ActivationResponse.success(Some(result))
                        }
                    } else {
                        // Any non-200 code is treated as a container failure. We still need to check whether
                        // there was a useful error message in there.
                        val errorContent = errorOpt.getOrElse {
                            JsString(s"The action invocation failed with the output: ${result.toString}")
                        }
                        ActivationResponse.containerError(errorContent)
                    }

                case Success(notAnObj) =>
                    // This should affect only blackbox containers, since our own containers should already test for that.
                    ActivationResponse.containerError(s"the action 'result' value is not an object: ${notAnObj.toString}")

                case Failure(t) =>
                    error(this, s"response did not json parse: $t")
                    ActivationResponse.containerError("the action did not produce a valid JSON response")
            }
        } getOrElse ActivationResponse.whiskError("failed to obtain action invocation response")
    }

    private def incrementUserActivationCounter(user: Subject): Int = {
        userActivationCounter get user() match {
            case Some(counter) => counter.next()
            case None =>
                val counter = new Counter()
                counter.next()
                userActivationCounter(user()) = counter
                counter.cur
        }
    }

    def getUserActivationCounts(): Map[String, JsObject] = {
        val subjects = userActivationCounter.keySet toList
        val groups = subjects.groupBy { user => user.substring(0, 1) }  // Any sort of partitioning will be ok wrt load balancer
        groups.keySet map { prefix => 
          val key = InvokerKeys.userActivationCount(instance) + "/" + prefix
          val users = groups.getOrElse(prefix, Set())
          val items = users map { u => (u, JsNumber(userActivationCounter.get(u) map { c => c.cur } getOrElse 0))}
          key -> JsObject(items toMap)
        } toMap
    }

    // -------------------------------------------------------------------------------------------------------------
    private def makeWhiskActivation(msg: Message, action: WhiskAction, auth: WhiskAuth, payload: JsObject,
                                    start: Instant, end: Instant, response: Option[(Int, String)], log: JsArray)(implicit transid: TransactionId): WhiskActivation = {
        WhiskActivation(
            namespace = auth.subject.namespace,
            name = action.name,
            version = action.version,
            publish = false,
            subject = auth.subject,
            activationId = msg.activationId,
            cause = msg.cause,
            start = start,
            end = end,
            response = processResponseContent(response),
            logs = ActivationLogs.serdes.read(log))
    }

    private val entityStore = WhiskEntityStore.datastore(config)
    private val authStore = WhiskAuthStore.datastore(config)
    private val activationStore = WhiskActivationStore.datastore(config)
    private val pool = new ContainerPool(config, instance)
    private val activationCounter = new Counter()
    private val userActivationCounter = new TrieMap[String, Counter]

    /**
     * Repeatedly updates the KV store as to the invoker's last check-in.
     */
    private val healthUpdatePeriodMillis = 2000
    private val kvStore = new ConsulKV(config.consulServer)
    private val reporter = new ConsulKVReporter(kvStore, 3000, healthUpdatePeriodMillis,
        InvokerKeys.hostname(instance),
        InvokerKeys.start(instance),
        InvokerKeys.status(instance),
        { () =>
            getUserActivationCounts() ++ 
            Map(InvokerKeys.activationCount(instance) -> activationCounter.cur.toJson)
        })

    // This will remove leftover action containers
    pool.killStragglers()(TransactionId.dontcare)

    // This is used for the getContainer endpoint used in perfContainer testing it is not real state
    private val activationIdMap = new TrieMap[ActivationId, String]
    def putContainerName(activationId: ActivationId, containerName: String) = activationIdMap += (activationId -> containerName)
    def getContainerName(activationId: ActivationId): Option[String] = activationIdMap get activationId
}

object Invoker {
    /**
     * An object which records the environment variables required for this component to run.
     */
    def requiredProperties =
        Map(logsDir -> null, dockerRegistry -> null) ++
            WhiskAuthStore.requiredProperties ++
            WhiskEntityStore.requiredProperties ++
            WhiskActivationStore.requiredProperties ++
            ContainerPool.requiredProperties ++
            edgeHost ++
            consulServer ++
            whiskVersion
}

object InvokerService {
    /**
     * An object which records the environment variables required for this component to run.
     */
    def requiredProperties = Invoker.requiredProperties ++ Dispatcher.requiredProperties

    private class ServiceBuilder(invoker: Invoker) extends Creator[InvokerServer] {
        def create = new InvokerServer {
            override val invokerInstance = invoker
        }
    }

    def main(args: Array[String]): Unit = {
        // load values for the required properties from the environment
        val config = new WhiskConfig(requiredProperties)

        if (config.isValid) {
            val instance = if (args.length > 0) args(1).toInt else 0
            val dispatcher = new Dispatcher(config, s"invoke${instance}", "invokers")
            val invoker = new Invoker(config, instance, Dispatcher.executionContext)

            SimpleExec.setVerbosity(Verbosity.Loud)
            invoker.setVerbosity(Verbosity.Loud)
            dispatcher.setVerbosity(Verbosity.Loud)
            dispatcher.addHandler(invoker, true)
            dispatcher.start()

            val port = config.servicePort.toInt
            BasicHttpService.startService("invoker", "0.0.0.0", port, new ServiceBuilder(invoker))
        }
    }

}
