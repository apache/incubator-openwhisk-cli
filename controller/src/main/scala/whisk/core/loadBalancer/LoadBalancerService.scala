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

package whisk.core.loadBalancer

import java.time.{ Clock, Instant }
import java.util.concurrent.atomic.AtomicInteger

import scala.collection.concurrent.TrieMap
import scala.concurrent.ExecutionContext
import scala.concurrent.Future
import scala.concurrent.Promise
import scala.concurrent.TimeoutException
import scala.concurrent.duration.DurationInt
import scala.concurrent.duration.FiniteDuration
import scala.language.postfixOps
import scala.util.Failure
import scala.util.Success

import akka.actor.ActorSystem
import akka.event.Logging.LogLevel

import spray.json.DefaultJsonProtocol.LongJsonFormat
import spray.json.{ JsObject, pimpAny }

import whisk.common.ConsulClient
import whisk.common.ConsulKV.LoadBalancerKeys
import whisk.common.ConsulKVReporter
import whisk.common.Counter
import whisk.common.Logging
import whisk.common.LoggingMarkers
import whisk.common.PrintStreamEmitter
import whisk.common.TransactionId
import whisk.connector.kafka.KafkaConsumerConnector
import whisk.connector.kafka.KafkaProducerConnector
import whisk.core.WhiskConfig
import whisk.core.WhiskConfig.{ consulServer, kafkaHost }
import whisk.core.connector.ActivationMessage
import whisk.core.connector.CompletionMessage
import whisk.core.entity.ActivationId
import whisk.core.entity.WhiskActivation

trait LoadBalancer {

    /**
     * Retrieves a per subject map of counts representing in-flight activations as seen by the load balancer
     *
     * @return a map where the key is the subject and the long is total issued activations by that user
     */
    def getActiveUserActivationCounts: Map[String, Long]

    /**
     * Publishes activation message on internal bus for the invoker to pick up.
     *
     * @param msg the activation message to publish on an invoker topic
     * @param timeout the desired active ack timeout
     * @param transid the transaction id for the request
     * @return future that provides an activation (result) if it is ready before timeout otherwise the future fails with ActiveAckTimeout
     */
    def publish(msg: ActivationMessage, timeout: FiniteDuration)(implicit transid: TransactionId): (Future[Unit], Future[WhiskActivation])

}

class LoadBalancerService(config: WhiskConfig,
                          verbosity: LogLevel)(
    implicit val actorSystem: ActorSystem)
    extends LoadBalancer with Logging {

    override def setVerbosity(level: LogLevel) = {
        super.setVerbosity(level)
        producer.setVerbosity(level)
    }

    /** The execution context for futures */
    implicit val executionContext: ExecutionContext = actorSystem.dispatcher

    private implicit val emitter: PrintStreamEmitter = this

    /**
     * Gets invoker health as a dictionary.
     */
    def getInvokerHealth(): JsObject = invokerHealth.getInvokerHealthJson()

    /**
     * Retrieves a per subject map of counts representing in-flight activations as seen by the load balancer
     *
     * @return a map where the key is the subject and the long is total issued activations by that user
     */
    override def getActiveUserActivationCounts: Map[String, Long] = activationBySubject.toMap mapValues { _.size.toLong }

    /**
     * Publishes message on kafka bus for the invoker to pick up.
     *
     * @param msg the activation message to publish on an invoker topic
     * @param transid the transaction id for the request
     * @return result a pair of Futures the first indicating completion of publishing and the second the completion of the action
     */
    def publish(msg: ActivationMessage, timeout: FiniteDuration)(implicit transid: TransactionId): (Future[Unit], Future[WhiskActivation]) = {
        getInvoker(msg) map {
            val start = transid.started(this, LoggingMarkers.CONTROLLER_KAFKA)
            invokerIndex =>
                val topic = ActivationMessage.invoker(invokerIndex)
                val subject = msg.subject()
                val entry = setupActivation(msg.activationId, subject, invokerIndex, timeout, transid)
                info(this, s"posting topic '$topic' with activation id '${msg.activationId}'")
                (producer.send(topic, msg) map { status =>
                    val counter = updateActivationCount(subject, invokerIndex)
                    transid.finished(this, start, s"user has ${counter} activations posted. Posted to ${status.topic()}[${status.partition()}][$status.offset()}]")
                }, entry.promise.future)
        } getOrElse {
            (Future.failed(new LoadBalancerException("no invokers available")),
                Future.failed(new LoadBalancerException("no invokers available")))
        }
    }

    /** Gets a producer which can publish messages to the kafka bus. */
    private val producer = new KafkaProducerConnector(config.kafkaHost, executionContext)

    private val invokerHealth = new InvokerHealth(config, invokerChangeCallback, () => producer.sentCount())

    // this must happen after certain instance members are defined
    setVerbosity(verbosity)

    /**
     * A map storing current activations based on ActivationId.
     * The promise value represents the obligation of writing the answer back.
     */
    case class ActivationEntry(id: ActivationId, subject: String, invokerIndex: Int, created: Instant, promise: Promise[WhiskActivation])
    type TrieSet[T] = TrieMap[T, Unit]
    private val activationById = new TrieMap[ActivationId, ActivationEntry]
    private val activationByInvoker = new TrieMap[Int, TrieSet[ActivationEntry]]
    private val activationBySubject = new TrieMap[String, TrieSet[ActivationEntry]]

    private val kv = new ConsulClient(config.consulServer)
    private val reporter = new ConsulKVReporter(kv, 3 seconds, 10 seconds,
        LoadBalancerKeys.hostnameKey,
        LoadBalancerKeys.startKey,
        LoadBalancerKeys.statusKey,
        { _ =>
            val activeCounts = getActiveCountByInvoker()
            val totalActiveCount = activeCounts.values.sum
            val health = invokerHealth.getInvokerHealth()
            implicit val sid = TransactionId.loadbalancer
            info(this, s"In flight: $totalActiveCount = [${activeCounts.mkString(", ")}]")
            info(this, s"Invoker health: [${health.mkString(", ")}]")
            Map(LoadBalancerKeys.invokerHealth -> getInvokerHealth(),
                LoadBalancerKeys.activationCountKey -> producer.sentCount().toJson)
        })

    private val consumer = new KafkaConsumerConnector(config.kafkaHost, "completions", "completed")
    consumer.setVerbosity(verbosity)
    consumer.onMessage((topic, partition, offset, bytes) => {
        val raw = new String(bytes, "utf-8")
        CompletionMessage(raw) match {
            case Success(m) => processCompletion(m)
            case Failure(t) => error(this, s"failed processing message: $raw with $t")
        }
    })

    /**
     * Tries to fill in the result slot (i.e., complete the promise) when a completion message arrives.
     * The promise is removed form the map when the result arrives or upon timeout.
     *
     * @param msg is the kafka message payload as Json
     */
    private def processCompletion(msg: CompletionMessage) = {
        implicit val tid = msg.transid
        val aid = msg.response.activationId
        info(this, s"received active ack for '$aid'")
        val response = msg.response
        activationById.remove(aid) match {
            case Some(entry @ ActivationEntry(_, subject, invokerIndex, _, p)) =>
                activationByInvoker.getOrElseUpdate(invokerIndex, new TrieSet[ActivationEntry]).remove(entry)
                activationBySubject.getOrElseUpdate(subject, new TrieSet[ActivationEntry]).remove(entry)
                p.trySuccess(response)
                info(this, s"processed active response for '$aid'")
            case None =>
                warn(this, s"processed active response for '$aid' which has no entry")
        }
    }

    /**
     * Creates an activation entry and insert into various maps.
     */
    private def setupActivation(activationId: ActivationId, subject: String, invokerIndex: Int, timeout: FiniteDuration, transid: TransactionId): ActivationEntry = {
        // either create a new promise or reuse a previous one for this activation if it exists
        val entry = activationById.getOrElseUpdate(activationId, {
            val promise = Promise[WhiskActivation]
            // store the promise to complete on success, or fail with ActiveAckTimeout if time is up
            // however, do not remove the entry as this is done only by processCompletion
            actorSystem.scheduler.scheduleOnce(timeout) {
                activationById.get(activationId).foreach { _ =>
                    if (promise.tryFailure(new ActiveAckTimeout(activationId))) {
                        info(this, "active response timed out")
                    }
                }
            }
            ActivationEntry(activationId, subject, invokerIndex, Instant.now(Clock.systemUTC()), promise)
        })
        activationByInvoker.getOrElseUpdate(invokerIndex, new TrieSet[ActivationEntry]).put(entry, {})
        activationBySubject.getOrElseUpdate(subject, new TrieSet[ActivationEntry]).put(entry, {})
        entry
    }

    /**
      * When invoker health detects a new invoker has come up, this callback is called.
      */
    private def invokerChangeCallback(invokerIndices: Array[Int]) = {
        invokerIndices.foreach { index =>
            val actSet = activationByInvoker.getOrElseUpdate(index, new TrieSet[ActivationEntry])
            actSet.keySet map { case actEntry @ ActivationEntry(activationId, subject, invokerIndex, _, promise) =>
                promise.tryFailure(new LoadBalancerException(s"Invoker $invokerIndex restarted"))
                activationById.remove(activationId)
                activationBySubject.get(subject) map { _.remove(actEntry) }
            }
            actSet.clear()
        }
    }

    private def updateActivationCount(user: String, invokerIndex: Int): Long = {
        userActivationCounter.getOrElseUpdate(user, new Counter()).next()
    }

    // Make a new immutable map so caller cannot mess up the state
    private def getActiveCountByInvoker(): Map[Int, Long] = activationByInvoker.toMap mapValues { _.size.toLong }

    // A count of how many activations have been posted to Kafka based on invoker index or user/subject.
    private val userActivationCounter = new TrieMap[String, Counter]


    /**
     * Determine which invoker this activation should go to.  Due to dynamic conditions, it may return no invoker.
     */
    private def getInvoker(msg: ActivationMessage): Option[Int] = {
        val (hash, count) = hashAndCountSubjectAction(msg)
        val invokers = invokerHealth.getCurStatus
        val numInvokers = invokers.length // The number of known invokers - not necessarily healthy
        if (numInvokers > 0) {
            val globalCount = msgCount.getAndIncrement()
            val hashCount = math.abs(hash + count / activationCountBeforeNextInvoker)
            val choice = pickInvoker(hashCount % numInvokers, numInvokers)
            getNext(choice, numInvokers, invokers)
        } else None
    }

    /**
     * Finds an available invoker starting at current index and trying for remaining indexes.
     */
    private def getNext(current: Int, remain: Int, invokers: Array[InvokerStatus]): Option[Int] = {
        if (remain > 0) {
            val choice = invokers(current)
            choice.status match {
                case true  => Some(choice.index)
                case false => getNext(nextInvoker(current, invokers.length), remain - 1, invokers)
            }
        } else {
            error(this, s"all invokers down")
            None
        }
    }

    /*
     * The path contains more than the action per se but seems sufficiently
     * isomorphic as the other parts are constant.  Extracting just the
     * action out specifically will involve some hairy regex's that the
     * Invoker is currently using and which is better avoid if/until
     * these are moved to some common place (like a subclass of Message?)
     */
    private def hashAndCountSubjectAction(msg: ActivationMessage): (Int, Int) = {
        val subject = msg.subject().toString()
        val path = msg.action.toString
        val hash = subject.hashCode() ^ path.hashCode()
        val key = (subject, path)
        val count = activationCountMap.get(key) match {
            case Some(counter) => counter.getAndIncrement()
            case None => {
                activationCountMap.put(key, new AtomicInteger(0))
                0
            }
        }
        return (hash, count)
    }

    private def pickInvoker(msgCount: Int, numInvokers : Int): Int = {
        val numInv = numInvokers
        if (numInv > 0) msgCount % numInv else 0
    }

    private def nextInvoker(i: Int, numInvokers: Int): Int = {
        val numInv = numInvokers
        if (numInv > 0) (i + 1) % numInv else 0
    }

    private val msgCount = new AtomicInteger(0)
    private val activationCountMap = TrieMap[(String, String), AtomicInteger]()

}

object LoadBalancerService {
    def requiredProperties = kafkaHost ++
        consulServer ++
        InvokerHealth.requiredProperties
}

private case class ActiveAckTimeout(activationId: ActivationId) extends TimeoutException
private case class LoadBalancerException(msg: String) extends Throwable(msg)
