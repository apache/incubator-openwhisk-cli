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

package whisk.core.entitlement

import scala.collection.concurrent.TrieMap

import whisk.common.Verbosity
import whisk.core.WhiskConfig
import whisk.core.entity.Subject
import whisk.common.TransactionId
import whisk.common.Logging


/**
 * A class tracking the rate of invocation (or any operation) by subject (any key really).
 * 
 * For now, we throttle only at a 1-minute granularity.
 */
class RateThrottler(config : WhiskConfig) extends Logging {

    // Parameters
    private val exemptSubject = ""  // We exempt nothing.
    private val maxPerMinute = 120
    private val maxPerHour = 3600

    // Implementation
    private val rateMap = new TrieMap[Subject, RateInfo]

    // Track the activation rate of one subject at multiple time granularities.
    class RateInfo extends Logging {
        setVerbosity(Verbosity.Noisy)
        var lastMin = getCurrentMinute
        var lastMinCount = 0
        var lastHour = getCurrentHour
        var lastHourCount = 0
        def check()(implicit transid: TransactionId): Boolean = {
            roll()
            lastMinCount = lastMinCount + 1
            lastHourCount = lastHourCount + 1
            //info(this, s"RateInfo: ${counts(counts.length-1)}")
            return lastMinCount <= maxPerMinute && lastHourCount <= maxPerHour
        }
        def roll()(implicit transid: TransactionId) = {
            val curMin = getCurrentMinute
            val curHour = getCurrentHour
            if (curMin != lastMin) {
                lastMin = curMin
                lastMinCount = 0
            }
            if (curHour != lastHour) {
                lastHour = curHour
                lastHourCount = 0
            }
        }
        private def getCurrentMinute = System.currentTimeMillis / (60 * 1000)
        private def getCurrentHour = System.currentTimeMillis / (3600 * 1000)
    }

    /*
     * Check whether the operation should be allowed to proceed.
     * Delegate to subject-based RateInfo to perform the check after checking for exemption(s).
     */
    def check(subject: Subject)(implicit transid: TransactionId): Boolean = {
        if (!exemptSubject.isEmpty && subject.toString == exemptSubject) {
            return true
        }
        if (!rateMap.isDefinedAt(subject)) {
            rateMap += subject -> new RateInfo()
        }
        info(this, s"RateThrottler.check: subject = ${subject.toString}")
        return rateMap.get(subject) map { _.check() } getOrElse true
    }
}


