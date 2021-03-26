/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package system.basic

import java.time.Instant

import scala.concurrent.duration.DurationInt
import scala.language.postfixOps

import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner

import common.ActivationResult
import common.TestHelpers
import common.TestUtils
import common.TestUtils._
import common.Wsk
import common.WskProps
import common.WskTestHelpers
import spray.json._
import spray.json.DefaultJsonProtocol._

import org.apache.openwhisk.http.Messages

@RunWith(classOf[JUnitRunner])
class WskCliBasicTests extends TestHelpers with WskTestHelpers {

  implicit val wskprops = WskProps()
  val wsk = new Wsk
  val defaultAction = Some(TestUtils.getTestActionFilename("hello.js"))

  behavior of "Wsk CLI"

  it should "reject creating duplicate entity" in withAssetCleaner(wskprops) { (wp, assetHelper) =>
    val name = "testDuplicateCreate"
    assetHelper.withCleaner(wsk.trigger, name) { (trigger, _) =>
      trigger.create(name)
    }
    assetHelper.withCleaner(wsk.action, name, confirmDelete = false) { (action, _) =>
      action.create(name, defaultAction, expectedExitCode = CONFLICT)
    }
  }

  it should "reject deleting entity in wrong collection" in withAssetCleaner(wskprops) { (wp, assetHelper) =>
    val name = "testCrossDelete"
    assetHelper.withCleaner(wsk.trigger, name) { (trigger, _) =>
      trigger.create(name)
    }
    wsk.action.delete(name, expectedExitCode = CONFLICT)
  }

  val WskCLI_RejUnauthAccess_exitCode = UNAUTHORIZED
  val WskCLI_RejUnauthAccess_stderr = "The supplied authentication is invalid"
  it should "reject unauthenticated access" in {
    implicit val new_wskprops = wskprops.copy(authKey = "xxx") //WskProps("xxx") // shadow properties
    wsk.namespace.get(expectedExitCode = WskCLI_RejUnauthAccess_exitCode)(new_wskprops).stderr should include(
      WskCLI_RejUnauthAccess_stderr)
  }

  behavior of "Wsk Package CLI"

  it should "create, update, get and list a package" in withAssetCleaner(wskprops) { (wp, assetHelper) =>
    val name = "testPackage"
    val params = Map("a" -> "A".toJson)
    assetHelper.withCleaner(wsk.pkg, name) { (pkg, _) =>
      pkg.create(name, parameters = params, shared = Some(true))
      pkg.create(name, update = true)
    }
    val stdout = wsk.pkg.get(name).stdout
    stdout should include regex (""""key": "a"""")
    stdout should include regex (""""value": "A"""")
    stdout should include regex (""""publish": true""")
    stdout should include regex (""""version": "0.0.2"""")
    wsk.pkg.list().stdout should include(name)
  }

  it should "create, and get a package summary" in withAssetCleaner(wskprops) { (wp, assetHelper) =>
    val packageName = "packageName"
    val actionName = "actionName"
    val packageAnnots = Map(
      "description" -> JsString("Package description"),
      "parameters" -> JsArray(
        JsObject("name" -> JsString("paramName1"), "description" -> JsString("Parameter description 1")),
        JsObject("name" -> JsString("paramName2"), "description" -> JsString("Parameter description 2"))))
    val actionAnnots = Map(
      "description" -> JsString("Action description"),
      "parameters" -> JsArray(
        JsObject("name" -> JsString("paramName1"), "description" -> JsString("Parameter description 1")),
        JsObject("name" -> JsString("paramName2"), "description" -> JsString("Parameter description 2"))))

    assetHelper.withCleaner(wsk.pkg, packageName) { (pkg, _) =>
      pkg.create(packageName, annotations = packageAnnots)
    }

    wsk.action.create(packageName + "/" + actionName, defaultAction, annotations = actionAnnots)
    val stdout = wsk.pkg.get(packageName, summary = true).stdout
    val ns = wsk.namespace.whois()
    wsk.action.delete(packageName + "/" + actionName)

    stdout should include regex (s"(?i)package /$ns/$packageName: Package description\\s*\\(parameters: paramName1, paramName2\\)")
    stdout should include regex (s"(?i)action /$ns/$packageName/$actionName: Action description\\s*\\(parameters: paramName1, paramName2\\)")
  }

  it should "create a package with a name that contains spaces" in withAssetCleaner(wskprops) { (wp, assetHelper) =>
    val name = "package with spaces"

    val res = assetHelper.withCleaner(wsk.pkg, name) { (pkg, _) =>
      pkg.create(name)
    }

    res.stdout should include(s"ok: created package $name")
  }

  it should "create a package, and get its individual fields" in withAssetCleaner(wskprops) {
    val name = "packageFields"
    val paramInput = Map("payload" -> "test".toJson)
    val successMsg = s"ok: got package $name, displaying field"

    (wp, assetHelper) =>
      assetHelper.withCleaner(wsk.pkg, name) { (pkg, _) =>
        pkg.create(name, parameters = paramInput)
      }

      val expectedParam = JsObject("payload" -> JsString("test"))
      val ns = wsk.namespace.whois()

      wsk.pkg
        .get(name, fieldFilter = Some("namespace"))
        .stdout should include regex (s"""(?i)$successMsg namespace\n"$ns"""")
      wsk.pkg.get(name, fieldFilter = Some("name")).stdout should include(s"""$successMsg name\n"$name"""")
      wsk.pkg.get(name, fieldFilter = Some("version")).stdout should include(s"""$successMsg version\n"0.0.1"""")
      wsk.pkg.get(name, fieldFilter = Some("publish")).stdout should include(s"""$successMsg publish\nfalse""")
      wsk.pkg.get(name, fieldFilter = Some("binding")).stdout should include regex (s"""\\{\\}""")
      wsk.pkg.get(name, fieldFilter = Some("invalid"), expectedExitCode = ERROR_EXIT).stderr should include(
        "error: Invalid field filter 'invalid'.")
  }

  it should "reject creation of duplication packages" in withAssetCleaner(wskprops) {
    val name = "dupePackage"

    (wp, assetHelper) =>
      assetHelper.withCleaner(wsk.pkg, name) { (pkg, _) =>
        pkg.create(name)
      }

      val stderr = wsk.pkg.create(name, expectedExitCode = CONFLICT).stderr
      stderr should include regex (s"""Unable to create package '$name': resource already exists \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject delete of package that does not exist" in {
    val name = "nonexistentPackage"
    val stderr = wsk.pkg.delete(name, expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to delete package '$name'. The requested resource does not exist. \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject get of package that does not exist" in {
    val name = "nonexistentPackage"
    val ns = wsk.namespace.whois()
    val stderr = wsk.pkg.get(name, expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to get package '$name': ${Messages.resourceDoesntExist(s"${ns}/${name}")} \\(code [0-9a-zA-Z_-]+\\)""")
  }

  behavior of "Wsk Action CLI"

  it should "create the same action twice with different cases" in withAssetCleaner(wskprops) { (wp, assetHelper) =>
    assetHelper.withCleaner(wsk.action, "TWICE") { (action, name) =>
      action.create(name, defaultAction)
    }
    assetHelper.withCleaner(wsk.action, "twice") { (action, name) =>
      action.create(name, defaultAction)
    }
  }

  it should "create, update, get and list an action" in withAssetCleaner(wskprops) { (wp, assetHelper) =>
    val name = "createAndUpdate"
    val file = Some(TestUtils.getTestActionFilename("hello.js"))
    val params = Map("a" -> "A".toJson)
    assetHelper.withCleaner(wsk.action, name) { (action, _) =>
      action.create(name, file, parameters = params)
      action.create(name, None, parameters = Map("b" -> "B".toJson), update = true)
    }

    val stdout = wsk.action.get(name).stdout
    stdout should not include (""""key": "a"""")
    stdout should not include (""""value": "A"""")
    stdout should include (""""key": "b""")
    stdout should include (""""value": "B"""")
    stdout should include (""""publish": false""")
    stdout should include (""""version": "0.0.2"""")
    wsk.action.list().stdout should include(name)
  }

  it should "reject create of an action that already exists" in withAssetCleaner(wskprops) {
    val name = "dupeAction"
    val file = Some(TestUtils.getTestActionFilename("echo.js"))

    (wp, assetHelper) =>
      assetHelper.withCleaner(wsk.action, name) { (action, _) =>
        action.create(name, file)
      }

      val stderr = wsk.action.create(name, file, expectedExitCode = CONFLICT).stderr
      stderr should include regex (s"""Unable to create action '$name': resource already exists \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject delete of action that does not exist" in {
    val name = "nonexistentAction"
    val stderr = wsk.action.delete(name, expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to delete action '$name'. The requested resource does not exist. \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject invocation of action that does not exist" in {
    val name = "nonexistentAction"
    val stderr = wsk.action.invoke(name, expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to invoke action '$name': The requested resource does not exist. \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject get of an action that does not exist" in {
    val name = "nonexistentAction"
    val stderr = wsk.action.get(name, expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to get action '$name': The requested resource does not exist. \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "create, and invoke an action that utilizes a docker container" in withAssetCleaner(wskprops) {
    val name = "dockerContainer"
    (wp, assetHelper) =>
      assetHelper.withCleaner(wsk.action, name) {
        // this docker image will be need to be pulled from dockerhub and hence has to be published there first
        (action, _) =>
          action.create(name, None, docker = Some("openwhisk/example"))
      }

      val args = Map("payload" -> "test".toJson)
      val run = wsk.action.invoke(name, args)
      withActivation(wsk.activation, run) { activation =>
        activation.response.result shouldBe Some(
          JsObject("args" -> args.toJson, "msg" -> "Hello from arbitrary C program!".toJson))
      }
  }

  it should "create, and invoke an action that utilizes dockerskeleton with native zip" in withAssetCleaner(wskprops) {
    val name = "dockerContainerWithZip"
    (wp, assetHelper) =>
      assetHelper.withCleaner(wsk.action, name) {
        // this docker image will be need to be pulled from dockerhub and hence has to be published there first
        (action, _) =>
          action.create(name, Some(TestUtils.getTestActionFilename("blackbox.zip")), kind = Some("native"))
      }

      val run = wsk.action.invoke(name, Map())
      withActivation(wsk.activation, run) { activation =>
        activation.response.result shouldBe Some(JsObject("msg" -> "hello zip".toJson))
        activation.logs shouldBe defined
        val logs = activation.logs.get.toString
        logs should include("This is an example zip used with the docker skeleton action.")
        logs should not include ("XXX_THE_END_OF_A_WHISK_ACTIVATION_XXX")
      }
  }

  it should "create, and invoke an action using a parameter file" in withAssetCleaner(wskprops) {
    val name = "paramFileAction"
    val file = Some(TestUtils.getTestActionFilename("argCheck.js"))
    val argInput = Some(TestUtils.getTestActionFilename("validInput2.json"))

    (wp, assetHelper) =>
      assetHelper.withCleaner(wsk.action, name) { (action, _) =>
        action.create(name, file)
      }

      val expectedOutput = JsObject("payload" -> JsString("test"))
      val run = wsk.action.invoke(name, parameterFile = argInput)
      withActivation(wsk.activation, run) { activation =>
        activation.response.result shouldBe Some(expectedOutput)
      }
  }

  /**
   * Tests creating an action from a malformed js file. This should fail in
   * some way - preferably when trying to create the action. If not, then
   * surely when it runs there should be some indication in the logs. Don't
   * think this is true currently.
   */
  it should "create and invoke action with malformed js resulting in activation error" in withAssetCleaner(wskprops) {
    (wp, assetHelper) =>
      val name = "MALFORMED"
      assetHelper.withCleaner(wsk.action, name) { (action, _) =>
        action.create(name, Some(TestUtils.getTestActionFilename("malformed.js")))
      }

      val run = wsk.action.invoke(name, Map("payload" -> "whatever".toJson))
      withActivation(wsk.activation, run) { activation =>
        activation.response.status shouldBe "action developer error"
        // representing nodejs giving an error when given malformed.js
        activation.response.result.get.toString should include("ReferenceError")
      }
  }

  it should "create and invoke a blocking action resulting in an application error response" in withAssetCleaner(
    wskprops) { (wp, assetHelper) =>
    val name = "applicationError"
    val strErrInput = Map("error" -> "Error message".toJson)
    val numErrInput = Map("error" -> 502.toJson)
    val boolErrInput = Map("error" -> true.toJson)

    assetHelper.withCleaner(wsk.action, name) { (action, _) =>
      action.create(name, Some(TestUtils.getTestActionFilename("echo.js")))
    }

    Seq(strErrInput, numErrInput, boolErrInput) foreach { input =>
      getJSONFromResponse(
        wsk.action.invoke(name, parameters = input, blocking = true, expectedExitCode = 246).stderr,
        wsk.isInstanceOf[Wsk])
        .fields("response")
        .asJsObject
        .fields("result")
        .asJsObject shouldBe input.toJson.asJsObject

      wsk.action
        .invoke(name, parameters = input, blocking = true, result = true, expectedExitCode = 246)
        .stderr
        .parseJson
        .asJsObject shouldBe input.toJson.asJsObject
    }
  }

  it should "create and invoke a blocking action resulting in an failed promise" in withAssetCleaner(wskprops) {
    (wp, assetHelper) =>
      val name = "errorResponseObject"
      assetHelper.withCleaner(wsk.action, name) { (action, _) =>
        action.create(name, Some(TestUtils.getTestActionFilename("asyncError.js")))
      }

      val stderr = wsk.action.invoke(name, blocking = true, expectedExitCode = 246).stderr
      ActivationResult.serdes.read(removeCLIHeader(stderr).parseJson).response.result shouldBe Some {
        JsObject("error" -> JsObject("msg" -> "failed activation on purpose".toJson))
      }
  }

  it should "invoke a blocking action and get only the result" in withAssetCleaner(wskprops) { (wp, assetHelper) =>
    val name = "basicInvoke"
    assetHelper.withCleaner(wsk.action, name) { (action, _) =>
      action.create(name, Some(TestUtils.getTestActionFilename("wc.js")))
    }

    wsk.action
      .invoke(name, Map("payload" -> "one two three".toJson), result = true)
      .stdout should include regex (""""count": 3""")
  }

  it should "create, and get an action summary" in withAssetCleaner(wskprops) { (wp, assetHelper) =>
    val name = "actionName"
    val annots = Map(
      "description" -> JsString("Action description"),
      "parameters" -> JsArray(
        JsObject("name" -> JsString("paramName1"), "description" -> JsString("Parameter description 1")),
        JsObject("name" -> JsString("paramName2"), "description" -> JsString("Parameter description 2"))))

    assetHelper.withCleaner(wsk.action, name) { (action, _) =>
      action.create(name, defaultAction, annotations = annots)
    }

    val stdout = wsk.action.get(name, summary = true).stdout
    val ns = wsk.namespace.whois()

    stdout should include regex (s"(?i)action /$ns/$name: Action description\\s*\\(parameters: paramName1, paramName2\\)")
  }

  it should "create an action with a name that contains spaces" in withAssetCleaner(wskprops) { (wp, assetHelper) =>
    val name = "action with spaces"

    val res = assetHelper.withCleaner(wsk.action, name) { (action, _) =>
      action.create(name, defaultAction)
    }

    res.stdout should include(s"ok: created action $name")
  }

  it should "create an action, and invoke an action that returns an empty JSON object" in withAssetCleaner(wskprops) {
    (wp, assetHelper) =>
      val name = "emptyJSONAction"

      assetHelper.withCleaner(wsk.action, name) { (action, _) =>
        action.create(name, Some(TestUtils.getTestActionFilename("emptyJSONResult.js")))
      }

      val stdout = wsk.action.invoke(name, result = true).stdout
      stdout.parseJson.asJsObject shouldBe JsObject()
  }

  it should "create, and invoke an action that times out to ensure the proper response is received" in withAssetCleaner(
    wskprops) { (wp, assetHelper) =>
    val name = "sleepAction"
    val params = Map("sleepTimeInMs" -> 100000.toJson)
    val allowedActionDuration = 120 seconds
    val res = assetHelper.withCleaner(wsk.action, name) { (action, _) =>
      action.create(name, Some(TestUtils.getTestActionFilename("sleep.js")), timeout = Some(allowedActionDuration))
      action.invoke(name, parameters = params, result = true, expectedExitCode = ACCEPTED)
    }

    res.stderr should include("""but the request has not yet finished""")
  }

  it should "create, and get docker action get ensure exec code is omitted" in withAssetCleaner(wskprops) {
    val name = "dockerContainer"
    (wp, assetHelper) =>
      assetHelper.withCleaner(wsk.action, name) { (action, _) =>
        action.create(name, None, docker = Some("fake-container"))
      }

      wsk.action.get(name).stdout should not include (""""code"""")
  }

  behavior of "Wsk Trigger CLI"

  it should "create, update, get, fire and list trigger" in withAssetCleaner(wskprops) { (wp, assetHelper) =>
    val ruleName = withTimestamp("r1toa1")
    val triggerName = withTimestamp("t1tor1")
    val actionName = withTimestamp("a1")
    val params = Map("a" -> "A".toJson)
    val ns = wsk.namespace.whois()

    assetHelper.withCleaner(wsk.trigger, triggerName) { (trigger, _) =>
      trigger.create(triggerName, parameters = params)
      trigger.create(triggerName, update = true)
    }

    assetHelper.withCleaner(wsk.action, actionName) { (action, name) =>
      action.create(name, defaultAction)
    }

    assetHelper.withCleaner(wsk.rule, ruleName) { (rule, name) =>
      rule.create(name, trigger = triggerName, action = actionName)
    }

    val trigger = wsk.trigger.get(triggerName)
    getJSONFromResponse(trigger.stdout, true).fields("parameters") shouldBe JsArray(
      JsObject("key" -> JsString("a"), "value" -> JsString("A")))
    getJSONFromResponse(trigger.stdout, true).fields("publish") shouldBe false.toJson
    getJSONFromResponse(trigger.stdout, true).fields("version") shouldBe "0.0.2".toJson

    val expectedRules = JsObject(
      ns + "/" + ruleName -> JsObject(
        "action" -> JsObject("name" -> JsString(actionName), "path" -> JsString(ns)),
        "status" -> JsString("active")))
    getJSONFromResponse(trigger.stdout, true).fields("rules") shouldBe expectedRules

    val dynamicParams = Map("t" -> "T".toJson)
    val run = wsk.trigger.fire(triggerName, dynamicParams)
    withActivation(wsk.activation, run) { activation =>
      activation.response.result shouldBe Some(dynamicParams.toJson)
      activation.duration shouldBe 0L // shouldn't exist but CLI generates it
      activation.end shouldBe Instant.EPOCH // shouldn't exist but CLI generates it
      activation.logs shouldBe defined
      activation.logs.get.size shouldBe 1

      val logEntry = activation.logs.get(0).parseJson.asJsObject
      val logs = JsArray(logEntry)
      val ruleActivationId: String = logEntry.fields("activationId").convertTo[String]
      val expectedLogs = JsArray(
        JsObject(
          "statusCode" -> JsNumber(0),
          "activationId" -> JsString(ruleActivationId),
          "success" -> JsBoolean(true),
          "rule" -> JsString(ns + "/" + ruleName),
          "action" -> JsString(ns + "/" + actionName)))
      logs shouldBe expectedLogs
    }

    val runWithNoParams = wsk.trigger.fire(triggerName, Map())
    withActivation(wsk.activation, runWithNoParams) { activation =>
      activation.response.result shouldBe Some(JsObject())
      activation.duration shouldBe 0L // shouldn't exist but CLI generates it
      activation.end shouldBe Instant.EPOCH // shouldn't exist but CLI generates it
    }

    wsk.trigger.list().stdout should include(triggerName)
  }

  it should "return error message when updating feed param on trigger that contains no feed param" in withAssetCleaner(
    wskprops) { (wp, assetHelper) =>
    val triggerName = withTimestamp("t1tor1")
    val ns = wsk.namespace.whois()
    val params = Map("a" -> "A".toJson)

    assetHelper.withCleaner(wsk.trigger, triggerName) { (trigger, _) =>
      trigger.create(triggerName, parameters = params)
    }
    wsk
      .cli(
        Seq("trigger", "update", triggerName, "-F", "feedParam", "feedParamVal", "--auth", wskprops.authKey) ++ wskprops.overrides,
        expectedExitCode = ERROR_EXIT)
      .stderr should include("this trigger does not contain a feed")
  }

  it should "return error message when creating feed with both --param and --trigger-param/--feed-param flags" in withAssetCleaner(
    wskprops) { (wp, assetHelper) =>
    val triggerName = withTimestamp("t1tor1")
    val ns = wsk.namespace.whois()

    var stderr =
      wsk
        .cli(
          Seq(
            "trigger",
            "create",
            triggerName,
            "-p",
            "a",
            "A",
            "-F",
            "feedParam",
            "feedParamVal",
            "--auth",
            wskprops.authKey) ++ wskprops.overrides,
          expectedExitCode = NOT_ALLOWED)
        .stderr
    stderr should include(
      "Incorrect usage. Cannot combine --feed-param or --trigger-param flag with neither --param nor --param-file flag")
  }

  it should "return error message when updating feed with both --param and --trigger-param/--feed-param flags" in withAssetCleaner(
    wskprops) { (wp, assetHelper) =>
    val triggerName = withTimestamp("t1tor1")
    val ns = wsk.namespace.whois()

    var stderr =
      wsk
        .cli(
          Seq(
            "trigger",
            "update",
            triggerName,
            "-p",
            "a",
            "A",
            "-T",
            "feedParam",
            "feedParamVal",
            "--auth",
            wskprops.authKey) ++ wskprops.overrides,
          expectedExitCode = NOT_ALLOWED)
        .stderr
    stderr should include(
      "Incorrect usage. Cannot combine --feed-param or --trigger-param flag with neither --param nor --param-file flag")
  }

  it should "return error message when creating feed with both --param-file and --trigger-param/--feed-param flags" in withAssetCleaner(
    wskprops) { (wp, assetHelper) =>
    val triggerName = withTimestamp("t1tor1")
    val ns = wsk.namespace.whois()
    val filePathString = TestUtils.getTestActionFilename("argCheck.js")

    var stderr =
      wsk
        .cli(
          Seq(
            "trigger",
            "create",
            triggerName,
            "--param-file",
            filePathString,
            "-F",
            "feedParam",
            "feedParamVal",
            "-T",
            "triggerParam",
            "triggerParamVal",
            "--auth",
            wskprops.authKey) ++ wskprops.overrides,
          expectedExitCode = NOT_ALLOWED)
        .stderr
    stderr should include(
      "Incorrect usage. Cannot combine --feed-param or --trigger-param flag with neither --param nor --param-file flag")
  }

  it should "create, and get a trigger summary" in withAssetCleaner(wskprops) { (wp, assetHelper) =>
    val name = "triggerName"
    val annots = Map(
      "description" -> JsString("Trigger description"),
      "parameters" -> JsArray(
        JsObject("name" -> JsString("paramName1"), "description" -> JsString("Parameter description 1")),
        JsObject("name" -> JsString("paramName2"), "description" -> JsString("Parameter description 2"))))

    assetHelper.withCleaner(wsk.trigger, name) { (trigger, _) =>
      trigger.create(name, annotations = annots)
    }

    val result = getJSONFromResponse(wsk.trigger.get(name).stdout, true)
    val ns = wsk.namespace.whois()

    result.fields("name") shouldBe name.toJson
    result.fields("namespace") shouldBe ns.toJson
    val receivedAnnotations = result.fields("annotations").convertTo[JsArray].elements
    val expectedAnnotations = JsArray(
      JsObject("key" -> JsString("description"), "value" -> JsString("Trigger description")),
      JsObject(
        "key" -> JsString("parameters"),
        "value" -> JsArray(
          JsObject("description" -> JsString("Parameter description 1"), "name" -> JsString("paramName1")),
          JsObject("description" -> JsString("Parameter description 2"), "name" -> JsString("paramName2"))))).elements

    receivedAnnotations should contain theSameElementsAs expectedAnnotations
  }

  it should "create a trigger with a name that contains spaces" in withAssetCleaner(wskprops) { (wp, assetHelper) =>
    val name = "trigger with spaces"

    val res = assetHelper.withCleaner(wsk.trigger, name) { (trigger, _) =>
      trigger.create(name)
    }

    res.stdout should include regex (s"ok: created trigger $name")
  }

  it should "create, and fire a trigger using a parameter file" in withAssetCleaner(wskprops) {
    val ruleName = withTimestamp("r1toa1")
    val triggerName = withTimestamp("paramFileTrigger")
    val actionName = withTimestamp("a1")
    val argInput = Some(TestUtils.getTestActionFilename("validInput2.json"))

    (wp, assetHelper) =>
      assetHelper.withCleaner(wsk.trigger, triggerName) { (trigger, _) =>
        trigger.create(triggerName)
      }

      assetHelper.withCleaner(wsk.action, actionName) { (action, name) =>
        action.create(name, defaultAction)
      }

      assetHelper.withCleaner(wsk.rule, ruleName) { (rule, name) =>
        rule.create(name, trigger = triggerName, action = actionName)
      }

      val expectedOutput = JsObject("payload" -> JsString("test"))
      val run = wsk.trigger.fire(triggerName, parameterFile = argInput)
      withActivation(wsk.activation, run) { activation =>
        activation.response.result shouldBe Some(expectedOutput)
      }
  }

  it should "create a trigger, and get its individual fields" in withAssetCleaner(wskprops) {
    val triggerName = "triggerFields"
    val ruleName = "triggerFieldsRules"
    val actionName = "triggerFieldsAction"
    val paramInput = Map("payload" -> "test".toJson)
    val successMsg = s"ok: got trigger $triggerName, displaying field"

    (wp, assetHelper) =>
      assetHelper.withCleaner(wsk.trigger, triggerName) { (trigger, name) =>
        trigger.create(name, parameters = paramInput)
      }
      assetHelper.withCleaner(wsk.action, actionName) { (action, name) =>
        action.create(name, defaultAction)
      }
      assetHelper.withCleaner(wsk.rule, ruleName) { (rule, name) =>
        rule.create(name, trigger = triggerName, action = actionName)
      }

      val expectedParam = JsObject("payload" -> JsString("test"))
      val ns = wsk.namespace.whois()

      wsk.trigger
        .get(triggerName, fieldFilter = Some("namespace"))
        .stdout should include regex (s"""(?i)$successMsg namespace\n"$ns"""")
      wsk.trigger.get(triggerName, fieldFilter = Some("name")).stdout should include(
        s"""$successMsg name\n"$triggerName"""")
      wsk.trigger.get(triggerName, fieldFilter = Some("version")).stdout should include(
        s"""$successMsg version\n"0.0.1"""")
      wsk.trigger.get(triggerName, fieldFilter = Some("publish")).stdout should include(
        s"""$successMsg publish\nfalse""")
      wsk.trigger.get(triggerName, fieldFilter = Some("annotations")).stdout should include(
        s"""$successMsg annotations\n[]""")
      wsk.trigger
        .get(triggerName, fieldFilter = Some("parameters"))
        .stdout should include regex (s"""$successMsg parameters\n\\[\\s+\\{\\s+"key":\\s+"payload",\\s+"value":\\s+"test"\\s+\\}\\s+\\]""")
      wsk.trigger.get(triggerName, fieldFilter = Some("limits")).stdout should include(s"""$successMsg limits\n{}""")
      wsk.trigger.get(triggerName, fieldFilter = Some("invalid"), expectedExitCode = ERROR_EXIT).stderr should include(
        "error: Invalid field filter 'invalid'.")

      val expectedRules = JsObject(
        ns + "/" + ruleName -> JsObject(
          "action" -> JsObject("name" -> JsString(actionName), "path" -> JsString(ns)),
          "status" -> JsString("active")))
      getJSONFromResponse(wsk.trigger.get(triggerName, fieldFilter = Some("rules")).stdout, isCli = true) shouldBe expectedRules
  }

  it should "create, and fire a trigger to ensure result is empty" in withAssetCleaner(wskprops) { (wp, assetHelper) =>
    val ruleName = withTimestamp("r1toa1")
    val triggerName = withTimestamp("emptyResultTrigger")
    val actionName = withTimestamp("a1")

    assetHelper.withCleaner(wsk.trigger, triggerName) { (trigger, _) =>
      trigger.create(triggerName)
    }

    assetHelper.withCleaner(wsk.action, actionName) { (action, name) =>
      action.create(name, defaultAction)
    }

    assetHelper.withCleaner(wsk.rule, ruleName) { (rule, name) =>
      rule.create(name, trigger = triggerName, action = actionName)
    }

    val run = wsk.trigger.fire(triggerName)
    withActivation(wsk.activation, run) { activation =>
      activation.response.result shouldBe Some(JsObject())
    }
  }

  it should "reject creation of duplicate triggers" in withAssetCleaner(wskprops) {
    val name = "dupeTrigger"

    (wp, assetHelper) =>
      assetHelper.withCleaner(wsk.trigger, name) { (trigger, _) =>
        trigger.create(name)
      }

      val stderr = wsk.trigger.create(name, expectedExitCode = CONFLICT).stderr
      stderr should include regex (s"""Unable to create trigger '$name': resource already exists \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject delete of trigger that does not exist" in {
    val name = "nonexistentTrigger"
    val stderr = wsk.trigger.delete(name, expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to get trigger '$name'. The requested resource does not exist. \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject get of trigger that does not exist" in {
    val name = "nonexistentTrigger"
    val stderr = wsk.trigger.get(name, expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to get trigger '$name': The requested resource does not exist. \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject firing of a trigger that does not exist" in {
    val name = "nonexistentTrigger"
    val stderr = wsk.trigger.fire(name, expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to fire trigger '$name': The requested resource does not exist. \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "create and fire a trigger with a rule whose action has been deleted" in withAssetCleaner(wskprops) {
    (wp, assetHelper) =>
      val ruleName1 = withTimestamp("r1toa1")
      val ruleName2 = withTimestamp("r2toa2")
      val triggerName = withTimestamp("t1tor1r2")
      val actionName1 = withTimestamp("a1")
      val actionName2 = withTimestamp("a2")
      val ns = wsk.namespace.whois()

      assetHelper.withCleaner(wsk.trigger, triggerName) { (trigger, _) =>
        trigger.create(triggerName)
        trigger.create(triggerName, update = true)
      }

      assetHelper.withCleaner(wsk.action, actionName1) { (action, name) =>
        action.create(name, defaultAction)
      }
      wsk.action.create(actionName2, defaultAction) // Delete this after the rule is created

      assetHelper.withCleaner(wsk.rule, ruleName1) { (rule, name) =>
        rule.create(name, trigger = triggerName, action = actionName1)
      }
      assetHelper.withCleaner(wsk.rule, ruleName2) { (rule, name) =>
        rule.create(name, trigger = triggerName, action = actionName2)
      }
      wsk.action.delete(actionName2)

      val run = wsk.trigger.fire(triggerName)
      withActivation(wsk.activation, run) { activation =>
        activation.duration shouldBe 0L // shouldn't exist but CLI generates it
        activation.end shouldBe Instant.EPOCH // shouldn't exist but CLI generates it
        activation.logs shouldBe defined
        activation.logs.get.size shouldBe 2

        val logEntry1 = activation.logs.get(0).parseJson.asJsObject
        val logEntry2 = activation.logs.get(1).parseJson.asJsObject
        val logs = JsArray(logEntry1, logEntry2)
        val ruleActivationId: String = if (logEntry1.getFields("activationId").size == 1) {
          logEntry1.fields("activationId").convertTo[String]
        } else {
          logEntry2.fields("activationId").convertTo[String]
        }
        val expectedLogs = JsArray(
          JsObject(
            "statusCode" -> JsNumber(0),
            "activationId" -> JsString(ruleActivationId),
            "success" -> JsBoolean(true),
            "rule" -> JsString(ns + "/" + ruleName1),
            "action" -> JsString(ns + "/" + actionName1)),
          JsObject(
            "statusCode" -> JsNumber(1),
            "success" -> JsBoolean(false),
            "error" -> JsString("The requested resource does not exist."),
            "rule" -> JsString(ns + "/" + ruleName2),
            "action" -> JsString(ns + "/" + actionName2)))
        logs shouldBe expectedLogs
      }
  }

  it should "display proper error when trigger is not associated with active rule" in withAssetCleaner(wskprops) {
    val triggerName = withTimestamp("noRuleTrigger")

    (wp, assetHelper) =>
      assetHelper.withCleaner(wsk.trigger, triggerName) { (trigger, _) =>
        trigger.create(triggerName)
      }

      wsk.trigger.fire(triggerName)
        .stdout should include regex(s"trigger /.*/$triggerName did not fire as it is not associated with an active rule")
  }

  behavior of "Wsk Rule CLI"

  it should "create rule, get rule, update rule and list rule" in withAssetCleaner(wskprops) { (wp, assetHelper) =>
    val ruleName = "listRules"
    val triggerName = "listRulesTrigger"
    val actionName = "listRulesAction"

    assetHelper.withCleaner(wsk.trigger, triggerName) { (trigger, name) =>
      trigger.create(name)
    }
    assetHelper.withCleaner(wsk.action, actionName) { (action, name) =>
      action.create(name, defaultAction)
    }
    assetHelper.withCleaner(wsk.rule, ruleName) { (rule, name) =>
      rule.create(name, trigger = triggerName, action = actionName)
    }

    // finally, we perform the update, and expect success this time
    wsk.rule.create(ruleName, trigger = triggerName, action = actionName, update = true)

    val stdout = wsk.rule.get(ruleName).stdout
    stdout should include(ruleName)
    stdout should include(triggerName)
    stdout should include(actionName)
    stdout should include regex (""""version": "0.0.2"""")
    wsk.rule.list().stdout should include(ruleName)
  }

  it should "create rule, get rule, ensure rule is enabled by default" in withAssetCleaner(wskprops) {
    (wp, assetHelper) =>
      val ruleName = "enabledRule"
      val triggerName = "enabledRuleTrigger"
      val actionName = "enabledRuleAction"

      assetHelper.withCleaner(wsk.trigger, triggerName) { (trigger, name) =>
        trigger.create(name)
      }
      assetHelper.withCleaner(wsk.action, actionName) { (action, name) =>
        action.create(name, defaultAction)
      }
      assetHelper.withCleaner(wsk.rule, ruleName) { (rule, name) =>
        rule.create(name, trigger = triggerName, action = actionName)
      }

      val stdout = wsk.rule.get(ruleName).stdout
      stdout should include regex (""""status":\s*"active"""")
  }

  it should "display a rule summary when --summary flag is used with 'wsk rule get'" in withAssetCleaner(wskprops) {
    (wp, assetHelper) =>
      val ruleName = "mySummaryRule"
      val triggerName = "summaryRuleTrigger"
      val actionName = "summaryRuleAction"

      assetHelper.withCleaner(wsk.trigger, triggerName) { (trigger, name) =>
        trigger.create(name)
      }
      assetHelper.withCleaner(wsk.action, actionName) { (action, name) =>
        action.create(name, defaultAction)
      }
      assetHelper.withCleaner(wsk.rule, ruleName, confirmDelete = false) { (rule, name) =>
        rule.create(name, trigger = triggerName, action = actionName)
      }

      // Summary namespace should match one of the allowable namespaces (typically 'guest')
      val ns = wsk.namespace.whois()
      val stdout = wsk.rule.get(ruleName, summary = true).stdout

      stdout should include regex (s"(?i)rule /$ns/$ruleName\\s*\\(status: active\\)")
  }

  it should "create a rule, and get its individual fields" in withAssetCleaner(wskprops) {
    val ruleName = "ruleFields"
    val triggerName = "ruleTriggerFields"
    val actionName = "ruleActionFields"
    val paramInput = Map("payload" -> "test".toJson)
    val successMsg = s"ok: got rule $ruleName, displaying field"

    (wp, assetHelper) =>
      assetHelper.withCleaner(wsk.trigger, triggerName) { (trigger, name) =>
        trigger.create(name)
      }
      assetHelper.withCleaner(wsk.action, actionName) { (action, name) =>
        action.create(name, defaultAction)
      }
      assetHelper.withCleaner(wsk.rule, ruleName) { (rule, name) =>
        rule.create(name, trigger = triggerName, action = actionName)
      }

      val ns = wsk.namespace.whois()
      wsk.rule
        .get(ruleName, fieldFilter = Some("namespace"))
        .stdout should include regex (s"""(?i)$successMsg namespace\n"$ns"""")
      wsk.rule.get(ruleName, fieldFilter = Some("name")).stdout should include(s"""$successMsg name\n"$ruleName"""")
      wsk.rule.get(ruleName, fieldFilter = Some("version")).stdout should include(s"""$successMsg version\n"0.0.1"\n""")
      wsk.rule.get(ruleName, fieldFilter = Some("status")).stdout should include(s"""$successMsg status\n"active"""")
      val trigger = wsk.rule.get(ruleName, fieldFilter = Some("trigger")).stdout
      trigger should include regex (s"""$successMsg trigger\n""")
      trigger should include(triggerName)
      trigger should not include (actionName)
      val action = wsk.rule.get(ruleName, fieldFilter = Some("action")).stdout
      action should include regex (s"""$successMsg action\n""")
      action should include(actionName)
      action should not include (triggerName)
  }

  it should "reject creation of duplicate rules" in withAssetCleaner(wskprops) {
    val ruleName = "dupeRule"
    val triggerName = "triggerName"
    val actionName = "actionName"

    (wp, assetHelper) =>
      assetHelper.withCleaner(wsk.trigger, triggerName) { (trigger, name) =>
        trigger.create(name)
      }
      assetHelper.withCleaner(wsk.action, actionName) { (action, name) =>
        action.create(name, defaultAction)
      }
      assetHelper.withCleaner(wsk.rule, ruleName) { (rule, name) =>
        rule.create(name, trigger = triggerName, action = actionName)
      }

      val stderr =
        wsk.rule.create(ruleName, trigger = triggerName, action = actionName, expectedExitCode = CONFLICT).stderr
      stderr should include regex (s"""Unable to create rule '$ruleName': resource already exists \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject delete of rule that does not exist" in {
    val name = "nonexistentRule"
    val stderr = wsk.rule.delete(name, expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to delete rule '$name'. The requested resource does not exist. \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject enable of rule that does not exist" in {
    val name = "nonexistentRule"
    val stderr = wsk.rule.enable(name, expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to enable rule '$name': The requested resource does not exist. \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject disable of rule that does not exist" in {
    val name = "nonexistentRule"
    val stderr = wsk.rule.disable(name, expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to disable rule '$name': The requested resource does not exist. \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject status of rule that does not exist" in {
    val name = "nonexistentRule"
    val stderr = wsk.rule.state(name, expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to get status of rule '$name': The requested resource does not exist. \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject get of rule that does not exist" in {
    val name = "nonexistentRule"
    val stderr = wsk.rule.get(name, expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to get rule '$name': The requested resource does not exist. \\(code [0-9a-zA-Z_-]+\\)""")
  }

  behavior of "Wsk Namespace CLI"

  def WskNsCLI_RetListOneNs_test(wsk: Wsk, wp: WskProps): Unit = {
    val lines = wsk.namespace.list()(wp).stdout.linesIterator.toSeq
    lines should have size 2
    lines.head shouldBe "namespaces"
    lines(1).trim should not be empty
  }
  it should "return a list of exactly one namespace" in {
    WskNsCLI_RetListOneNs_test(wsk, wskprops)
  }

  it should "list entities in default namespace" in {
    wsk.namespace.get(expectedExitCode = SUCCESS_EXIT)(wskprops).stdout should include("default")
  }

  behavior of "Wsk Activation CLI"

  it should "create a trigger, and fire a trigger to get its individual fields from an activation" in withAssetCleaner(
    wskprops) { (wp, assetHelper) =>
    val ruleName = withTimestamp("r1toa1")
    val triggerName = withTimestamp("activationFields")
    val actionName = withTimestamp("a1")

    assetHelper.withCleaner(wsk.trigger, triggerName) { (trigger, _) =>
      trigger.create(triggerName)
    }

    assetHelper.withCleaner(wsk.action, actionName) { (action, name) =>
      action.create(name, defaultAction)
    }

    assetHelper.withCleaner(wsk.rule, ruleName) { (rule, name) =>
      rule.create(name, trigger = triggerName, action = actionName)
    }

    val ns = wsk.namespace.whois()
    val run = wsk.trigger.fire(triggerName)
    withActivation(wsk.activation, run) { activation =>
      var result = wsk.activation.get(Some(activation.activationId))
      getJSONFromResponse(result.stdout, true).fields("namespace").convertTo[String] shouldBe ns
      getJSONFromResponse(result.stdout, true).fields("name").convertTo[String] shouldBe triggerName
      getJSONFromResponse(result.stdout, true).fields("version").convertTo[String] shouldBe "0.0.1"
      getJSONFromResponse(result.stdout, true).fields("publish") shouldBe false.toJson
      getJSONFromResponse(result.stdout, true).fields("subject").convertTo[String].length should not be (0)
      getJSONFromResponse(result.stdout, true).fields("activationId").convertTo[String] shouldBe activation.activationId
      getJSONFromResponse(result.stdout, true).fields("start") should not be JsObject()
      getJSONFromResponse(result.stdout, true).fields("end") shouldBe 0.toJson
      getJSONFromResponse(result.stdout, true).fields("duration") shouldBe 0.toJson
      getJSONFromResponse(result.stdout, true).fields("annotations").convertTo[JsArray].elements.length shouldBe 0
    }
  }

  it should "reject get of activation that does not exist" in {
    val name = "0" * 32
    val stderr = wsk.activation.get(Some(name), expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to get activation '$name': The requested resource does not exist. \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject logs of activation that does not exist" in {
    val name = "0" * 32
    val stderr = wsk.activation.logs(Some(name), expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to get logs for activation '$name': The requested resource does not exist. \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject result of activation that does not exist" in {
    val name = "0" * 32
    val stderr = wsk.activation.result(Some(name), expectedExitCode = NOT_FOUND).stderr
    stderr should include regex (s"""Unable to get result for activation '$name': The requested resource does not exist. \\(code [0-9a-zA-Z_-]+\\)""")
  }

  it should "reject activation request when using activation ID with --last Flag" in withAssetCleaner(wskprops) {
    (wp, assetHelper) =>
      val auth: Seq[String] = Seq("--auth", wskprops.authKey)

      val lastId = "dummyActivationId"
      val tooManyArgsMsg = s"${lastId}. An activation ID is required."
      val invalidField = s"Invalid field filter '${lastId}'."

      val invalidCmd = Seq(
        (Seq("activation", "get", s"$lastId", "publish", "--last"), tooManyArgsMsg),
        (Seq("activation", "get", s"$lastId", "--last"), invalidField),
        (Seq("activation", "logs", s"$lastId", "--last"), tooManyArgsMsg),
        (Seq("activation", "result", s"$lastId", "--last"), tooManyArgsMsg))

      invalidCmd foreach {
        case (cmd, err) =>
          val stderr = wsk.cli(cmd ++ wskprops.overrides ++ auth, expectedExitCode = ERROR_EXIT).stderr
          stderr should include(err)
      }
  }
}
