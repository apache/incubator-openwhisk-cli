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

package commands

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	reflect "github.com/goccy/go-reflect"
	
	"github.com/apache/openwhisk-cli/wski18n"
	"github.com/apache/openwhisk-client-go/whisk"

	"github.com/fatih/color"
	"github.com/mattn/go-colorable"
	"github.com/spf13/cobra"
)

const (
	MEMORY_LIMIT      = 256
	TIMEOUT_LIMIT     = 60000
	LOGSIZE_LIMIT     = 10
	CONCURRENCY_LIMIT = 1
	ACTIVATION_ID     = "activationId"
	WEB_EXPORT_ANNOT  = "web-export"
	RAW_HTTP_ANNOT    = "raw-http"
	FINAL_ANNOT       = "final"
	WEB_SECURE_ANNOT  = "require-whisk-auth"
	NODE_JS_EXT       = ".js"
	PYTHON_EXT        = ".py"
	JAVA_EXT          = ".jar"
	SWIFT_EXT         = ".swift"
	ZIP_EXT           = ".zip"
	PHP_EXT           = ".php"
	BAL_BIN_EXT       = ".balx"
	RUBY_EXT          = ".rb"
	RUST_EXT          = ".rs"
	GO_EXT            = ".go"
	NODE_JS           = "nodejs"
	PYTHON            = "python"
	JAVA              = "java"
	SWIFT             = "swift"
	PHP               = "php"
	RUBY              = "ruby"
	RUST              = "rust"
	GO                = "go"
	BAL               = "ballerina"
	DEFAULT           = "default"
	BLACKBOX          = "blackbox"
	SEQUENCE          = "sequence"
	FETCH_CODE        = true
	DO_NOT_FETCH_CODE = false
	ACTION_UPDATE     = true
	ACTION_CREATE     = false
	MAX_JS_INT        = 1<<53 - 1
)

var actionCmd = &cobra.Command{
	Use:   "action",
	Short: wski18n.T("work with actions"),
}

var actionCreateCmd = &cobra.Command{
	Use:           "create ACTION_NAME ACTION",
	Short:         wski18n.T("create a new action"),
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE:       SetupClientConfig,
	RunE: func(cmd *cobra.Command, args []string) error {
		var action *whisk.Action
		var err error

		if whiskErr := CheckArgs(
			args,
			1,
			2,
			"Action create",
			wski18n.T("An action name and code artifact are required.")); whiskErr != nil {
			return whiskErr
		}

		if action, err = parseAction(cmd, args, false); err != nil {
			return actionParseError(cmd, args, err)
		}

		if action, err = augmentAction(cmd, args, action, ACTION_CREATE); err != nil {
			return actionParseError(cmd, args, err)
		}

		if _, _, err = Client.Actions.Insert(action, false); err != nil {
			return actionInsertError(action, err)
		}

		printActionCreated(action.Name)

		return nil
	},
}

var actionUpdateCmd = &cobra.Command{
	Use:           "update ACTION_NAME [ACTION]",
	Short:         wski18n.T("update an existing action, or create an action if it does not exist"),
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE:       SetupClientConfig,
	RunE: func(cmd *cobra.Command, args []string) error {
		var action *whisk.Action
		var err error

		if whiskErr := CheckArgs(
			args,
			1,
			2,
			"Action update",
			wski18n.T("An action name is required. A code artifact is optional.")); whiskErr != nil {
			return whiskErr
		}

		if action, err = parseAction(cmd, args, true); err != nil {
			return actionParseError(cmd, args, err)
		}

		if action, err = augmentAction(cmd, args, action, ACTION_UPDATE); err != nil {
			return actionParseError(cmd, args, err)
		}

		if _, _, err = Client.Actions.Insert(action, true); err != nil {
			return actionInsertError(action, err)
		}

		printActionUpdated(action.Name)

		return nil
	},
}

var actionInvokeCmd = &cobra.Command{
	Use:           "invoke ACTION_NAME",
	Short:         wski18n.T("invoke action"),
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE:       SetupClientConfig,
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error
		var qualifiedName = new(QualifiedName)
		var parameters interface{}

		if whiskErr := CheckArgs(
			args,
			1,
			1,
			"Action invoke",
			wski18n.T("An action name is required.")); whiskErr != nil {
			return whiskErr
		}

		if qualifiedName, err = NewQualifiedName(args[0]); err != nil {
			return NewQualifiedNameError(args[0], err)
		}

		parameters = getParameters(Flags.common.param, false, false)
		blocking := Flags.common.blocking || Flags.action.result
		resultOnly := Flags.action.result
		header := !resultOnly

		res, err := invokeAction(
			*qualifiedName,
			parameters,
			blocking,
			resultOnly)

		return printInvocationResponse(*qualifiedName, blocking, header, res, err)
	},
}

func invokeAction(
	qualifiedName QualifiedName,
	parameters interface{},
	blocking bool,
	result bool) (map[string]interface{}, error) {
	// TODO remove all global modifiers
	Client.Namespace = qualifiedName.GetNamespace()
	res, _, err := Client.Actions.Invoke(
		qualifiedName.GetEntityName(),
		parameters,
		blocking,
		result)
	return res, err
}

func printInvocationResponse(
	qualifiedName QualifiedName,
	blocking bool,
	header bool,
	result map[string]interface{},
	err error) error {
	if err == nil {
		printInvocationMsg(qualifiedName, blocking, header, result, color.Output)
	} else {
		if !blocking {
			return handleInvocationError(err, qualifiedName.GetEntityName())
		} else {
			return printFailedBlockingInvocationResponse(qualifiedName, header, result, err)
		}
	}

	return err
}

func printFailedBlockingInvocationResponse(
	qualifiedName QualifiedName,
	header bool,
	result map[string]interface{},
	err error) error {
	if isBlockingTimeout(err) {
		printBlockingTimeoutMsg(
			qualifiedName.GetNamespace(),
			qualifiedName.GetEntityName(),
			getValueFromJSONResponse(ACTIVATION_ID, result))
		return err
	} else if isApplicationError(err) {
		printInvocationMsg(
			qualifiedName,
			true,
			header,
			result,
			colorable.NewColorableStderr())
		return err
	} else {
		return handleInvocationError(err, qualifiedName.GetEntityName())
	}
}

var actionGetCmd = &cobra.Command{
	Use:           "get ACTION_NAME [FIELD_FILTER | --summary | --url]",
	Short:         wski18n.T("get action"),
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE:       SetupClientConfig,
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error
		var field string
		var action *whisk.Action
		var qualifiedName = new(QualifiedName)
		var fetchCode bool

		if whiskErr := CheckArgs(args, 1, 2, "Action get", wski18n.T("An action name is required.")); whiskErr != nil {
			return whiskErr
		}

		if !Flags.action.url && !Flags.common.summary && len(args) > 1 {
			field = args[1]

			if !fieldExists(&whisk.Action{}, field) {
				return invalidFieldFilterError(field)
			}
		}

		if qualifiedName, err = NewQualifiedName(args[0]); err != nil {
			return NewQualifiedNameError(args[0], err)
		}

		Client.Namespace = qualifiedName.GetNamespace()
		fetchCode = cmd.LocalFlags().Changed(SAVE_AS_FLAG) || cmd.LocalFlags().Changed(SAVE_FLAG)

		if action, _, err = Client.Actions.Get(qualifiedName.GetEntityName(), fetchCode); err != nil {
			return actionGetError(qualifiedName.GetEntityName(), fetchCode, err)
		}

		if Flags.action.url {
			actionURL, err := action.ActionURL(Properties.APIHost,
				DefaultOpenWhiskApiPath,
				Properties.APIVersion,
				qualifiedName.GetPackageName())
			if err != nil {
				errStr := wski18n.T("Invalid host address '{{.host}}': {{.err}}",
					map[string]interface{}{"host": Properties.APIHost, "err": err})
				werr := whisk.MakeWskError(errors.New(errStr), whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
				return werr
			}
			printActionGetWithURL(qualifiedName.GetEntity(), actionURL)
		} else if Flags.common.summary {
			printSummary(action)
		} else if cmd.LocalFlags().Changed(SAVE_AS_FLAG) || cmd.LocalFlags().Changed(SAVE_FLAG) {
			return saveCode(*action, Flags.action.saveAs)
		} else {
			if len(field) > 0 {
				printActionGetWithField(qualifiedName.GetEntityName(), field, action)
			} else {
				printActionGet(qualifiedName.GetEntityName(), action)
			}
		}

		return nil
	},
}

var actionDeleteCmd = &cobra.Command{
	Use:           "delete ACTION_NAME",
	Short:         wski18n.T("delete action"),
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE:       SetupClientConfig,
	RunE: func(cmd *cobra.Command, args []string) error {
		var qualifiedName = new(QualifiedName)
		var err error

		if whiskErr := CheckArgs(
			args,
			1,
			1,
			"Action delete",
			wski18n.T("An action name is required.")); whiskErr != nil {
			return whiskErr
		}

		if qualifiedName, err = NewQualifiedName(args[0]); err != nil {
			return NewQualifiedNameError(args[0], err)
		}

		Client.Namespace = qualifiedName.GetNamespace()

		if _, err = Client.Actions.Delete(qualifiedName.GetEntityName()); err != nil {
			return actionDeleteError(qualifiedName.GetEntityName(), err)
		}

		printActionDeleted(qualifiedName.GetEntityName())

		return nil
	},
}

var actionListCmd = &cobra.Command{
	Use:           "list [ NAMESPACE | PACKAGE_NAME ]",
	Short:         wski18n.T("list all actions in a namespace or actions contained in a package"),
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE:       SetupClientConfig,
	RunE: func(cmd *cobra.Command, args []string) error {
		var qualifiedName = new(QualifiedName)
		var actions []whisk.Action
		var err error

		if whiskErr := CheckArgs(
			args,
			0,
			1,
			"Action list",
			wski18n.T("An optional namespace is the only valid argument.")); whiskErr != nil {
			return whiskErr
		}

		if len(args) == 1 {
			if qualifiedName, err = NewQualifiedName(args[0]); err != nil {
				return NewQualifiedNameError(args[0], err)
			}

			Client.Namespace = qualifiedName.GetNamespace()
		}

		options := &whisk.ActionListOptions{
			Skip:  Flags.common.skip,
			Limit: Flags.common.limit,
		}

		if actions, _, err = Client.Actions.List(qualifiedName.GetEntityName(), options); err != nil {
			return actionListError(qualifiedName.GetEntityName(), options, err)
		}

		sortByName := Flags.common.nameSort
		printList(actions, sortByName)

		return nil
	},
}

func parseAction(cmd *cobra.Command, args []string, update bool) (*whisk.Action, error) {
	var err error
	var existingAction *whisk.Action
	var paramArgs []string
	var annotArgs []string
	var parameters interface{}
	var annotations interface{}

	var qualifiedName = new(QualifiedName)

	if qualifiedName, err = NewQualifiedName(args[0]); err != nil {
		return nil, NewQualifiedNameError(args[0], err)
	}

	Client.Namespace = qualifiedName.GetNamespace()
	action := new(whisk.Action)
	action.Name = qualifiedName.GetEntityName()
	action.Namespace = qualifiedName.GetNamespace()
	action.Limits = getLimits(
		cmd.LocalFlags().Changed(MEMORY_FLAG),
		cmd.LocalFlags().Changed(LOG_SIZE_FLAG),
		cmd.LocalFlags().Changed(TIMEOUT_FLAG),
		cmd.LocalFlags().Changed(CONCURRENCY_FLAG),
		Flags.action.memory,
		Flags.action.logsize,
		Flags.action.timeout,
		Flags.action.concurrency)

	paramArgs = Flags.common.param
	annotArgs = Flags.common.annotation

	if len(paramArgs) > 0 {
		if parameters, err = getJSONFromStrings(paramArgs, true); err != nil {
			return nil, getJSONFromStringsParamError(paramArgs, true, err)
		}

		action.Parameters = parameters.(whisk.KeyValueArr)
	}

	if len(annotArgs) > 0 {
		if annotations, err = getJSONFromStrings(annotArgs, true); err != nil {
			return nil, getJSONFromStringsAnnotError(annotArgs, true, err)
		}

		action.Annotations = annotations.(whisk.KeyValueArr)
	}

	if len(Flags.action.kind) > 0 && len(Flags.action.docker) > 0 {
		errStr := wski18n.T("Cannot specify both --kind and --docker at the same time.")
		return nil, whisk.MakeWskError(errors.New(errStr), whisk.NOT_ALLOWED, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
	}

	if Flags.action.copy {
		var copiedQualifiedName = new(QualifiedName)

		if copiedQualifiedName, err = NewQualifiedName(args[1]); err != nil {
			return nil, NewQualifiedNameError(args[1], err)
		}

		Client.Namespace = copiedQualifiedName.GetNamespace()

		if existingAction, _, err = Client.Actions.Get(copiedQualifiedName.GetEntityName(), FETCH_CODE); err != nil {
			return nil, actionGetError(copiedQualifiedName.GetEntityName(), FETCH_CODE, err)
		}

		Client.Namespace = qualifiedName.GetNamespace()
		action.Exec = existingAction.Exec
		action.Parameters = append(action.Parameters, existingAction.Parameters...)
		action.Annotations = append(action.Annotations, existingAction.Annotations...)
	} else if Flags.action.sequence {
		if len(args) == 2 {
			action.Exec = new(whisk.Exec)
			action.Exec.Kind = SEQUENCE
			action.Exec.Components = csvToQualifiedActions(args[1])
		} else {
			return nil, noArtifactError()
		}
	} else if len(args) > 1 || len(Flags.action.docker) > 0 {
		action.Exec, err = getExec(args, Flags.action)
		if err != nil {
			return nil, err
		}
	} else if !update {
		return nil, noArtifactError()
	}

	if update {
		action.DelAnnotations = Flags.action.delAnnotation
	}
	whisk.Debug(whisk.DbgInfo, "Parsed action struct: %#v\n", action)
	return action, err
}

func augmentAction(cmd *cobra.Command, args []string, action *whisk.Action, update bool) (*whisk.Action, error) {
	var err error
	var existingAction *whisk.Action = nil
	var augmentedAction *whisk.Action = new(whisk.Action)
	*augmentedAction = *action

	if update {
		if existingAction, _, err = Client.Actions.Get(action.Name, DO_NOT_FETCH_CODE); err != nil {
			whiskErr, isWhiskError := err.(*whisk.WskError)

			if (isWhiskError && whiskErr.ExitCode != whisk.EXIT_CODE_NOT_FOUND) || !isWhiskError {
				return nil, actionGetError(action.Name, DO_NOT_FETCH_CODE, err)
			}
		}
	}

	// Augment the action's annotations with the --web related annotations
	if augmentedAction, err = augmentWebArg(cmd, args, action, augmentedAction, existingAction); err != nil {
		return nil, err
	}

	// Augment the action's annotations with the --web-secure related annotations
	if augmentedAction, err = augmentWebSecureArg(cmd, args, action, augmentedAction, existingAction); err != nil {
		return nil, err
	}

	whisk.Debug(whisk.DbgInfo, "Augmented action struct: %#v\n", augmentedAction)
	return augmentedAction, err
}

func augmentWebArg(cmd *cobra.Command, args []string, action *whisk.Action, augmentedAction *whisk.Action, existingAction *whisk.Action) (*whisk.Action, error) {
	var err error
	preserveAnnotations := action.Annotations == nil

	if cmd.LocalFlags().Changed(WEB_FLAG) {
		augmentedAction.Annotations, err = webAction(Flags.action.web, action.Annotations, action.Name, preserveAnnotations, existingAction)
		if existingAction != nil && err == nil {
			// Always carry forward any existing --web-secure annotation value
			// Although it can be overwritten later if --web-secure is set
			webSecureAnnotations := getWebSecureAnnotations(existingAction)
			if len(webSecureAnnotations) > 0 {
				augmentedAction.Annotations = augmentedAction.Annotations.AppendKeyValueArr(webSecureAnnotations)
			}
		}
	}

	if err != nil {
		return nil, err
	}

	whisk.Debug(whisk.DbgInfo, "augmentWebArg: Augmented action struct: %#v\n", augmentedAction)
	return augmentedAction, nil
}

/*
 * Return a whisk.Action augmented with --web-secure annotation updates
 * originalAction:  a action constructed from command line argument
 * action:          an action constructed from command line args + possible other augmentation (i.e. --web annotations)
 * existingAction:  on an action update, this is the existing action
 */
func augmentWebSecureArg(cmd *cobra.Command, args []string, originalAction *whisk.Action, action *whisk.Action, existingAction *whisk.Action) (*whisk.Action, error) {
	preserveAnnotations := action.Annotations == nil
	var augmentedAction *whisk.Action = new(whisk.Action)
	*augmentedAction = *action
	disableWebAction := strings.ToLower(Flags.action.web) == "false" || strings.ToLower(Flags.action.web) == "no"
	isWebSecureFlagValidToUse := action.WebAction() || (existingAction != nil && existingAction.WebAction() && !disableWebAction)

	// Process the --web-secure flag when set
	if cmd.LocalFlags().Changed(WEB_SECURE_FLAG) {
		// The --web-secure option is only valid when:
		//   1. action --web is set to either true or raw (i.e. web-export annotation is true)
		//   -OR-
		//   2. existing action web-export annotation is true && action --web is not false/no
		whisk.Debug(whisk.DbgInfo, "disableWebAction: %v  isWebSecureFlagValidToUse: %v\n", disableWebAction, isWebSecureFlagValidToUse)
		if !isWebSecureFlagValidToUse {
			return nil, webSecureUsageError()
		}

		// Carry forward some or all of the existing action's annotations
		//   all  -> if original command line had at least one annotation specified
		//   some -> if original command line had NO annotations, carry forward web/websecure annotation values
		if existingAction != nil {
			if preserveAnnotations {
				augmentedAction.Annotations = action.Annotations.AppendKeyValueArr(existingAction.Annotations)
			} else {
				augmentedAction.Annotations = action.Annotations.AppendKeyValueArr(getWebActionAnnotations(existingAction))
				augmentedAction.Annotations = augmentedAction.Annotations.AppendKeyValueArr(getWebSecureAnnotations(existingAction))
			}
		}
		// when "--web-secure false", need to delete require-whisk-auth annotation
		secureSecret := webSecureSecret(Flags.action.websecure) // will be false when "--web-secure false"
		existingSecret := augmentedAction.Annotations.GetValue(WEB_SECURE_ANNOT)
		_, disableSecurity := secureSecret.(bool)
		if existingSecret != nil && disableSecurity {
			augmentedAction.DelAnnotations = []string{"require-whisk-auth"}
		}
		augmentedAction.Annotations = updateWebSecureAnnotation(Flags.action.websecure, augmentedAction.Annotations)
	}

	whisk.Debug(whisk.DbgInfo, "augmentWebSecureArg: Augmented action struct: %#v\n", augmentedAction)
	return augmentedAction, nil
}

func getExec(args []string, params ActionFlags) (*whisk.Exec, error) {
	var err error
	var code string
	var exec *whisk.Exec

	exec = new(whisk.Exec)
	kind := params.kind
	isNative := params.native
	docker := params.docker
	mainEntry := params.main
	ext := ""

	if len(args) == 2 {
		artifact := args[1]
		ext = filepath.Ext(artifact)
		code, err = ReadFile(artifact)

		if err != nil {
			whisk.Debug(whisk.DbgError, "ReadFile(%s) error: %s\n", artifact, err)
			return nil, err
		}

		if ext == ZIP_EXT || ext == JAVA_EXT || ext == BAL_BIN_EXT {
			code = base64.StdEncoding.EncodeToString([]byte(code))
		}

		exec.Code = &code
	} else if len(args) == 1 && len(docker) == 0 {
		return nil, noArtifactError()
	} else if len(args) > 1 {
		return nil, noArtifactError()
	}

	if len(kind) > 0 {
		exec.Kind = kind
	} else if len(docker) > 0 || isNative {
		exec.Kind = BLACKBOX
		if isNative {
			exec.Image = "openwhisk/dockerskeleton"
		} else {
			exec.Image = docker
		}
	} else if ext == SWIFT_EXT {
		exec.Kind = fmt.Sprintf("%s:%s", SWIFT, DEFAULT)
	} else if ext == NODE_JS_EXT {
		exec.Kind = fmt.Sprintf("%s:%s", NODE_JS, DEFAULT)
	} else if ext == PYTHON_EXT {
		exec.Kind = fmt.Sprintf("%s:%s", PYTHON, DEFAULT)
	} else if ext == JAVA_EXT {
		exec.Kind = fmt.Sprintf("%s:%s", JAVA, DEFAULT)
	} else if ext == PHP_EXT {
		exec.Kind = fmt.Sprintf("%s:%s", PHP, DEFAULT)
	} else if ext == RUBY_EXT {
		exec.Kind = fmt.Sprintf("%s:%s", RUBY, DEFAULT)
	} else if ext == RUST_EXT {
		exec.Kind = fmt.Sprintf("%s:%s", RUST, DEFAULT)
	} else if ext == GO_EXT {
		exec.Kind = fmt.Sprintf("%s:%s", GO, DEFAULT)
	} else if ext == BAL_BIN_EXT {
		exec.Kind = fmt.Sprintf("%s:%s", BAL, DEFAULT)
	} else {
		if ext == ZIP_EXT {
			return nil, zipKindError()
		} else {
			return nil, extensionError(ext)
		}
	}

	// Error if entry point is not specified for Java
	if len(mainEntry) != 0 {
		exec.Main = mainEntry
	} else {
		if exec.Kind == "java" {
			return nil, javaEntryError()
		}
	}

	return exec, nil
}

func getBinaryKindExtension(runtime string) (extension string) {
	switch strings.ToLower(runtime) {
	case JAVA:
		extension = JAVA_EXT
	case BAL:
		extension = BAL_BIN_EXT
	default:
		extension = ZIP_EXT
	}

	return extension
}

func getKindExtension(runtime string) (extension string) {
	switch strings.ToLower(runtime) {
	case NODE_JS:
		extension = NODE_JS_EXT
	case PYTHON:
		extension = PYTHON_EXT
	case SWIFT:
		fallthrough
	case PHP:
		extension = fmt.Sprintf(".%s", runtime)
	case RUBY:
		extension = RUBY_EXT
	case RUST:
		extension = RUST_EXT
	case GO:
		extension = GO_EXT
	}

	return extension
}

func saveCode(action whisk.Action, filename string) (err error) {
	var code string
	var runtime string
	var exec whisk.Exec

	exec = *action.Exec
	runtime = strings.Split(exec.Kind, ":")[0]

	if strings.ToLower(runtime) == BLACKBOX && exec.Code == nil && *exec.Binary == false {
		return cannotSaveImageError()
	} else if strings.ToLower(runtime) == SEQUENCE {
		return cannotSaveSequenceError()
	}

	if exec.Code != nil {
		code = *exec.Code
	}

	if *exec.Binary {
		decoded, _ := base64.StdEncoding.DecodeString(code)
		code = string(decoded)

		if len(filename) == 0 {
			filename = action.Name + getBinaryKindExtension(runtime)
		}
	} else {
		if len(filename) == 0 {
			filename = action.Name + getKindExtension(runtime)
		}
	}

	if exists, err := FileExists(filename); err != nil {
		return err
	} else if exists {
		return fileExistsError(filename)
	}

	if err := writeFile(filename, code); err != nil {
		return err
	}

	pwd, err := os.Getwd()
	if err != nil {
		whisk.Debug(whisk.DbgError, "os.Getwd() error: %s\n", err)
		return err
	}

	savedPath := fmt.Sprintf("%s%s%s", pwd, string(os.PathSeparator), filename)

	printSavedActionCodeSuccess(savedPath)

	return nil
}

func webAction(webMode string, annotations whisk.KeyValueArr, entityName string, preserveAnnotations bool, existingAction *whisk.Action) (whisk.KeyValueArr, error) {
	switch strings.ToLower(webMode) {
	case "yes":
		fallthrough
	case "true":
		return webActionAnnotations(preserveAnnotations, annotations, entityName, addWebAnnotations, existingAction)
	case "no":
		fallthrough
	case "false":
		return webActionAnnotations(preserveAnnotations, annotations, entityName, deleteWebAnnotations, existingAction)
	case "raw":
		return webActionAnnotations(preserveAnnotations, annotations, entityName, addRawAnnotations, existingAction)
	default:
		return nil, webInputError(webMode)
	}
}

type WebActionAnnotationMethod func(annotations whisk.KeyValueArr) whisk.KeyValueArr

func webActionAnnotations(
	preserveAnnotations bool,
	annotations whisk.KeyValueArr,
	entityName string,
	webActionAnnotationMethod WebActionAnnotationMethod,
	existingAction *whisk.Action) (whisk.KeyValueArr, error) {

	if preserveAnnotations && existingAction != nil {
		annotations = whisk.KeyValueArr.AppendKeyValueArr(annotations, existingAction.Annotations)
	}

	annotations = webActionAnnotationMethod(annotations)

	return annotations, nil
}

func addWebAnnotations(annotations whisk.KeyValueArr) whisk.KeyValueArr {
	annotations = deleteWebAnnotationKeys(annotations)
	annotations = addKeyValue(WEB_EXPORT_ANNOT, true, annotations)
	annotations = addKeyValue(RAW_HTTP_ANNOT, false, annotations)
	annotations = addKeyValue(FINAL_ANNOT, true, annotations)

	return annotations
}

func deleteWebAnnotations(annotations whisk.KeyValueArr) whisk.KeyValueArr {
	annotations = deleteWebAnnotationKeys(annotations)
	annotations = addKeyValue(WEB_EXPORT_ANNOT, false, annotations)
	annotations = addKeyValue(RAW_HTTP_ANNOT, false, annotations)
	annotations = addKeyValue(FINAL_ANNOT, false, annotations)

	return annotations
}

func addRawAnnotations(annotations whisk.KeyValueArr) whisk.KeyValueArr {
	annotations = deleteWebAnnotationKeys(annotations)
	annotations = addKeyValue(WEB_EXPORT_ANNOT, true, annotations)
	annotations = addKeyValue(RAW_HTTP_ANNOT, true, annotations)
	annotations = addKeyValue(FINAL_ANNOT, true, annotations)

	return annotations
}

func deleteWebAnnotationKeys(annotations whisk.KeyValueArr) whisk.KeyValueArr {
	annotations = deleteKey(WEB_EXPORT_ANNOT, annotations)
	annotations = deleteKey(RAW_HTTP_ANNOT, annotations)
	annotations = deleteKey(FINAL_ANNOT, annotations)

	return annotations
}

func getWebActionAnnotations(action *whisk.Action) whisk.KeyValueArr {
	var webKvArr = make(whisk.KeyValueArr, 3, 3)
	var j = 0

	var i = action.Annotations.FindKeyValue(WEB_EXPORT_ANNOT)
	if i > -1 {
		webKvArr[j] = action.Annotations[i]
		j++
	}
	i = action.Annotations.FindKeyValue(RAW_HTTP_ANNOT)
	if i > -1 {
		webKvArr[j] = action.Annotations[i]
		j++
	}
	i = action.Annotations.FindKeyValue(FINAL_ANNOT)
	if i > -1 {
		webKvArr[j] = action.Annotations[i]
		j++
	}
	return webKvArr[0:j]
}

func getWebSecureAnnotations(action *whisk.Action) whisk.KeyValueArr {
	var webKvArr = make(whisk.KeyValueArr, 1, 1)
	var j = 0

	var i = action.Annotations.FindKeyValue(WEB_SECURE_ANNOT)
	if i > -1 {
		webKvArr[j] = action.Annotations[i]
		j++
	}

	return webKvArr[0:j]
}

/*
 * Update the existing annotations with the web security annotation
 * If the current web security setting and existing setting are the "same", keep the existing value
 *   -> checking for the same "--web-secure true" setting means just checking if the two values are integers
 * If the current web security setting is "false", remove any existing setting
 */
func updateWebSecureAnnotation(websecure string, annotations whisk.KeyValueArr) whisk.KeyValueArr {
	secureSecret := webSecureSecret(websecure) // will be false when "--web-secure false"
	existingSecret := annotations.GetValue(WEB_SECURE_ANNOT)
	_, disableSecurity := secureSecret.(bool)
	_, newSecretIsInt := secureSecret.(int64)
	var existingSecretIsInt bool = false
	if existingSecret != nil {
		_, existingSecretIsInt = existingSecret.(json.Number)
	}

	if existingSecretIsInt && newSecretIsInt {
		whisk.Debug(whisk.DbgInfo, "Retaining existing secret number\n")
	} else if existingSecret != nil && disableSecurity {
		whisk.Debug(whisk.DbgInfo, "disabling web-secure; deleting annotation: %v\n", WEB_SECURE_ANNOT)
		annotations = deleteKey(WEB_SECURE_ANNOT, annotations)
	} else {
		whisk.Debug(whisk.DbgInfo, "Setting %v annotation; prior secret %v new secret %v\n",
			WEB_SECURE_ANNOT, reflect.TypeOf(existingSecret), reflect.TypeOf(secureSecret))
		annotations = annotations.AddOrReplace(&whisk.KeyValue{Key: WEB_SECURE_ANNOT, Value: secureSecret})
	}

	return annotations
}

//
// Generate a secret according to the --web-secure setting
//  true:   return a random int64
//  false:  return false, meaning no secret was returned
//  string: return the same string
func webSecureSecret(webSecureMode string) interface{} {
	switch strings.ToLower(webSecureMode) {
	case "true":
		return genWebActionSecureKey()
	case "false":
		return false
	default:
		return webSecureMode
	}
}

func getLimits(memorySet bool, logSizeSet bool, timeoutSet bool, concurrencySet bool, memory int, logSize int, timeout int, concurrency int) *whisk.Limits {
	var limits *whisk.Limits

	if memorySet || logSizeSet || timeoutSet || concurrencySet {
		limits = new(whisk.Limits)

		if memorySet {
			limits.Memory = &memory
		}

		if logSizeSet {
			limits.Logsize = &logSize
		}

		if timeoutSet {
			limits.Timeout = &timeout
		}

		if concurrencySet {
			limits.Concurrency = &concurrency
		}
	}

	return limits
}

func nestedError(errorMessage string, err error) error {
	return whisk.MakeWskErrorFromWskError(
		errors.New(errorMessage),
		err,
		whisk.EXIT_CODE_ERR_GENERAL,
		whisk.DISPLAY_MSG,
		whisk.DISPLAY_USAGE)
}

func nonNestedError(errorMessage string) error {
	return whisk.MakeWskError(
		errors.New(errorMessage),
		whisk.EXIT_CODE_ERR_USAGE,
		whisk.DISPLAY_MSG,
		whisk.DISPLAY_USAGE)
}

func actionParseError(cmd *cobra.Command, args []string, err error) error {
	whisk.Debug(whisk.DbgError, "parseAction(%s, %s) error: %s\n", cmd.Name(), args, err)

	errMsg := wski18n.T(
		"Invalid argument(s). {{.required}}",
		map[string]interface{}{
			"required": err,
		})

	return nestedError(errMsg, err)
}

func actionInsertError(action *whisk.Action, err error) error {
	whisk.Debug(whisk.DbgError, "Client.Actions.Insert(%#v, false) error: %s\n", action, err)

	errMsg := wski18n.T(
		"Unable to create action '{{.name}}': {{.err}}",
		map[string]interface{}{
			"name": action.Name,
			"err":  err,
		})

	return nestedError(errMsg, err)
}

func getJSONFromStringsParamError(params []string, keyValueFormat bool, err error) error {
	whisk.Debug(whisk.DbgError, "getJSONFromStrings(%#v, %t) failed: %s\n", params, keyValueFormat, err)

	errMsg := wski18n.T(
		"Invalid parameter argument '{{.param}}': {{.err}}",
		map[string]interface{}{
			"param": fmt.Sprintf("%#v", params),
			"err":   err,
		})

	return nestedError(errMsg, err)
}

func getJSONFromStringsAnnotError(annots []string, keyValueFormat bool, err error) error {
	whisk.Debug(whisk.DbgError, "getJSONFromStrings(%#v, %t) failed: %s\n", annots, keyValueFormat, err)

	errMsg := wski18n.T(
		"Invalid annotation argument '{{.annotation}}': {{.err}}",
		map[string]interface{}{
			"annotation": fmt.Sprintf("%#v", annots),
			"err":        err,
		})

	return nestedError(errMsg, err)
}

func invalidFieldFilterError(field string) error {
	errMsg := wski18n.T(
		"Invalid field filter '{{.arg}}'.",
		map[string]interface{}{
			"arg": field,
		})

	return nonNestedError(errMsg)
}

func actionDeleteError(entityName string, err error) error {
	whisk.Debug(whisk.DbgError, "Client.Actions.Delete(%s) error: %s\n", entityName, err)

	errMsg := wski18n.T(
		"Unable to delete action '{{.name}}': {{.err}}",
		map[string]interface{}{
			"name": entityName,
			"err":  err,
		})

	return nestedError(errMsg, err)
}

func actionGetError(entityName string, fetchCode bool, err error) error {
	whisk.Debug(whisk.DbgError, "Client.Actions.Get(%s, %t) error: %s\n", entityName, fetchCode, err)

	errMsg := wski18n.T(
		"Unable to get action '{{.name}}': {{.err}}",
		map[string]interface{}{
			"name": entityName,
			"err":  err,
		})

	return nestedError(errMsg, err)
}

func handleInvocationError(err error, entityName string) error {
	whisk.Debug(
		whisk.DbgError,
		"Client.Actions.Invoke(%s) error: %s\n",
		entityName,
		err)

	errMsg := wski18n.T(
		"Unable to invoke action '{{.name}}': {{.err}}",
		map[string]interface{}{
			"name": entityName,
			"err":  err,
		})

	return nestedError(errMsg, err)
}

func actionListError(entityName string, options *whisk.ActionListOptions, err error) error {
	whisk.Debug(whisk.DbgError, "Client.Actions.List(%s, %#v) error: %s\n", entityName, options, err)

	errMsg := wski18n.T(
		"Unable to obtain the list of actions for namespace '{{.name}}': {{.err}}",
		map[string]interface{}{
			"name": getClientNamespace(),
			"err":  err,
		})

	return nestedError(errMsg, err)
}

func webInputError(arg string) error {
	errMsg := wski18n.T(
		"Invalid argument '{{.arg}}' for --web flag. Valid input consist of 'yes', 'true', 'raw', 'false', or 'no'.",
		map[string]interface{}{
			"arg": arg,
		})

	return nonNestedError(errMsg)
}

func webSecureUsageError() error {
	errMsg := wski18n.T("The --web-secure option is only valid when the --web option is enabled.")
	return nonNestedError(errMsg)
}

func zipKindError() error {
	errMsg := wski18n.T("creating an action from a .zip artifact requires specifying the action kind explicitly")

	return nonNestedError(errMsg)
}

func noArtifactError() error {
	errMsg := wski18n.T("An action name and code artifact are required.")

	return nonNestedError(errMsg)
}

func extensionError(extension string) error {
	errMsg := wski18n.T(
		"'{{.name}}' is not a supported action runtime",
		map[string]interface{}{
			"name": extension,
		})

	return nonNestedError(errMsg)
}

func javaEntryError() error {
	errMsg := wski18n.T("Java actions require --main to specify the fully-qualified name of the main class")

	return nonNestedError(errMsg)
}

func cannotSaveImageError() error {
	return nonNestedError(wski18n.T("Cannot save Docker images"))
}

func cannotSaveSequenceError() error {
	return nonNestedError(wski18n.T("Cannot save action sequences"))
}

func fileExistsError(file string) error {
	errMsg := wski18n.T("The file '{{.file}}' already exists", map[string]interface{}{
		"file": file,
	})

	return nonNestedError(errMsg)
}

func printActionCreated(entityName string) {
	fmt.Fprintf(
		color.Output,
		wski18n.T(
			"{{.ok}} created action {{.name}}\n",
			map[string]interface{}{
				"ok":   color.GreenString("ok:"),
				"name": boldString(entityName),
			}))
}

func printActionUpdated(entityName string) {
	fmt.Fprintf(
		color.Output,
		wski18n.T(
			"{{.ok}} updated action {{.name}}\n",
			map[string]interface{}{
				"ok":   color.GreenString("ok:"),
				"name": boldString(entityName),
			}))
}

func printBlockingTimeoutMsg(namespace string, entityName string, activationID interface{}) {
	fmt.Fprintf(
		colorable.NewColorableStderr(),
		wski18n.T(
			"{{.ok}} invoked /{{.namespace}}/{{.name}}, but the request has not yet finished, with id {{.id}}\n",
			map[string]interface{}{
				"ok":        color.GreenString("ok:"),
				"namespace": boldString(namespace),
				"name":      boldString(entityName),
				"id":        boldString(activationID),
			}))
}

func printInvocationMsg(
	qualifiedName QualifiedName,
	blocking bool,
	header bool,
	response map[string]interface{},
	outputStream io.Writer) {
	if header {
		fmt.Fprintf(
			outputStream,
			wski18n.T(
				"{{.ok}} invoked /{{.namespace}}/{{.name}} with id {{.id}}\n",
				map[string]interface{}{
					"ok":        color.GreenString("ok:"),
					"namespace": boldString(qualifiedName.GetNamespace()),
					"name":      boldString(qualifiedName.GetEntityName()),
					"id":        boldString(getValueFromJSONResponse(ACTIVATION_ID, response)),
				}))
	}

	if blocking {
		printJSON(response, outputStream)
	}
}

func printActionGetWithField(entityName string, field string, action *whisk.Action) {
	fmt.Fprintf(
		color.Output,
		wski18n.T(
			"{{.ok}} got action {{.name}}, displaying field {{.field}}\n",
			map[string]interface{}{
				"ok":    color.GreenString("ok:"),
				"name":  boldString(entityName),
				"field": boldString(field),
			}))

	printField(action, field)
}

func printActionGetWithURL(entityName string, actionURL string) {
	fmt.Fprintf(
		color.Output,
		wski18n.T("{{.ok}} got action {{.name}}\n",
			map[string]interface{}{
				"ok":   color.GreenString("ok:"),
				"name": boldString(entityName),
			}))
	fmt.Println(actionURL)
}

func printActionGet(entityName string, action *whisk.Action) {
	fmt.Fprintf(
		color.Output,
		wski18n.T("{{.ok}} got action {{.name}}\n",
			map[string]interface{}{
				"ok":   color.GreenString("ok:"),
				"name": boldString(entityName),
			}))

	printJSON(action)
}

func printActionDeleted(entityName string) {
	fmt.Fprintf(
		color.Output,
		wski18n.T(
			"{{.ok}} deleted action {{.name}}\n",
			map[string]interface{}{
				"ok":   color.GreenString("ok:"),
				"name": boldString(entityName),
			}))
}

func printSavedActionCodeSuccess(name string) {
	fmt.Fprintf(
		color.Output,
		wski18n.T(
			"{{.ok}} saved action code to {{.name}}\n",
			map[string]interface{}{
				"ok":   color.GreenString("ok:"),
				"name": boldString(name),
			}))
}

// Generate a random number to be used as a web action's require-whisk-auth secret
func genWebActionSecureKey() int64 {
	r := rand.New(rand.NewSource(time.Now().Unix()))

	// Truncate integer for API GW interoperability
	return r.Int63() & MAX_JS_INT
}

// Check if the specified action is a web-action
func isWebAction(client *whisk.Client, qname QualifiedName) (*whisk.Action, error) {
	var err error = nil

	savedNs := client.Namespace
	client.Namespace = qname.GetNamespace()
	fullActionName := "/" + qname.GetNamespace() + "/" + qname.GetEntityName()

	action, _, err := client.Actions.Get(qname.GetEntityName(), DO_NOT_FETCH_CODE)

	if err != nil {
		whisk.Debug(whisk.DbgError, "client.Actions.Get(%s, %t) error: %s\n", fullActionName, DO_NOT_FETCH_CODE, err)
		whisk.Debug(whisk.DbgError, "Unable to obtain action '%s' for web action validation\n", fullActionName)
		errMsg := wski18n.T("Unable to get action '{{.name}}': {{.err}}",
			map[string]interface{}{"name": fullActionName, "err": err})
		err = whisk.MakeWskErrorFromWskError(errors.New(errMsg), err, whisk.EXIT_CODE_ERR_NETWORK, whisk.DISPLAY_MSG,
			whisk.NO_DISPLAY_USAGE)
	} else {
		err = errors.New(wski18n.T("Action '{{.name}}' is not a web action. Issue 'wsk action update \"{{.name}}\" --web true' to convert the action to a web action.",
			map[string]interface{}{"name": fullActionName}))

		if action.WebAction() {
			err = nil
		}
	}

	client.Namespace = savedNs

	return action, err
}

func init() {
	actionCreateCmd.Flags().BoolVar(&Flags.action.native, "native", false, wski18n.T("treat ACTION as native action (zip file provides a compatible executable to run)"))
	actionCreateCmd.Flags().StringVar(&Flags.action.docker, "docker", "", wski18n.T("use provided docker image (a path on DockerHub) to run the action"))
	actionCreateCmd.Flags().BoolVar(&Flags.action.copy, "copy", false, wski18n.T("treat ACTION as the name of an existing action"))
	actionCreateCmd.Flags().BoolVar(&Flags.action.sequence, "sequence", false, wski18n.T("treat ACTION as comma separated sequence of actions to invoke"))
	actionCreateCmd.Flags().StringVar(&Flags.action.kind, "kind", "", wski18n.T("the `KIND` of the action runtime (example: swift:default, nodejs:default)"))
	actionCreateCmd.Flags().StringVar(&Flags.action.main, "main", "", wski18n.T("the name of the action entry point (function or fully-qualified method name when applicable)"))
	actionCreateCmd.Flags().IntVarP(&Flags.action.timeout, TIMEOUT_FLAG, "t", TIMEOUT_LIMIT, wski18n.T("the timeout `LIMIT` in milliseconds after which the action is terminated"))
	actionCreateCmd.Flags().IntVarP(&Flags.action.memory, MEMORY_FLAG, "m", MEMORY_LIMIT, wski18n.T("the maximum memory `LIMIT` in MB for the action"))
	actionCreateCmd.Flags().IntVarP(&Flags.action.logsize, LOG_SIZE_FLAG, "l", LOGSIZE_LIMIT, wski18n.T("the maximum log size `LIMIT` in MB for the action"))
	actionCreateCmd.Flags().IntVarP(&Flags.action.concurrency, CONCURRENCY_FLAG, "c", CONCURRENCY_LIMIT, wski18n.T("the maximum intra-container concurrent activation `LIMIT` for the action"))
	actionCreateCmd.Flags().StringSliceVarP(&Flags.common.annotation, "annotation", "a", nil, wski18n.T("annotation values in `KEY VALUE` format"))
	actionCreateCmd.Flags().StringVarP(&Flags.common.annotFile, "annotation-file", "A", "", wski18n.T("`FILE` containing annotation values in JSON format"))
	actionCreateCmd.Flags().StringSliceVarP(&Flags.common.param, "param", "p", nil, wski18n.T("parameter values in `KEY VALUE` format"))
	actionCreateCmd.Flags().StringVarP(&Flags.common.paramFile, "param-file", "P", "", wski18n.T("`FILE` containing parameter values in JSON format"))
	actionCreateCmd.Flags().StringVar(&Flags.action.web, WEB_FLAG, "", wski18n.T("treat ACTION as a web action, a raw HTTP web action, or as a standard action; yes | true = web action, raw = raw HTTP web action, no | false = standard action"))
	actionCreateCmd.Flags().StringVar(&Flags.action.websecure, WEB_SECURE_FLAG, "", wski18n.T("secure the web action. where `SECRET` is true, false, or any string. Only valid when the ACTION is a web action"))

	actionUpdateCmd.Flags().BoolVar(&Flags.action.native, "native", false, wski18n.T("treat ACTION as native action (zip file provides a compatible executable to run)"))
	actionUpdateCmd.Flags().StringVar(&Flags.action.docker, "docker", "", wski18n.T("use provided docker image (a path on DockerHub) to run the action"))
	actionUpdateCmd.Flags().BoolVar(&Flags.action.copy, "copy", false, wski18n.T("treat ACTION as the name of an existing action"))
	actionUpdateCmd.Flags().BoolVar(&Flags.action.sequence, "sequence", false, wski18n.T("treat ACTION as comma separated sequence of actions to invoke"))
	actionUpdateCmd.Flags().StringVar(&Flags.action.kind, "kind", "", wski18n.T("the `KIND` of the action runtime (example: swift:default, nodejs:default)"))
	actionUpdateCmd.Flags().StringVar(&Flags.action.main, "main", "", wski18n.T("the name of the action entry point (function or fully-qualified method name when applicable)"))
	actionUpdateCmd.Flags().IntVarP(&Flags.action.timeout, TIMEOUT_FLAG, "t", TIMEOUT_LIMIT, wski18n.T("the timeout `LIMIT` in milliseconds after which the action is terminated"))
	actionUpdateCmd.Flags().IntVarP(&Flags.action.memory, MEMORY_FLAG, "m", MEMORY_LIMIT, wski18n.T("the maximum memory `LIMIT` in MB for the action"))
	actionUpdateCmd.Flags().IntVarP(&Flags.action.logsize, LOG_SIZE_FLAG, "l", LOGSIZE_LIMIT, wski18n.T("the maximum log size `LIMIT` in MB for the action"))
	actionUpdateCmd.Flags().IntVarP(&Flags.action.concurrency, CONCURRENCY_FLAG, "c", CONCURRENCY_LIMIT, wski18n.T("the maximum intra-container concurrent activation `LIMIT` for the action"))
	actionUpdateCmd.Flags().StringSliceVarP(&Flags.common.annotation, "annotation", "a", []string{}, wski18n.T("annotation values in `KEY VALUE` format"))
	actionUpdateCmd.Flags().StringVarP(&Flags.common.annotFile, "annotation-file", "A", "", wski18n.T("`FILE` containing annotation values in JSON format"))
	actionUpdateCmd.Flags().StringSliceVarP(&Flags.common.param, "param", "p", []string{}, wski18n.T("parameter values in `KEY VALUE` format"))
	actionUpdateCmd.Flags().StringVarP(&Flags.common.paramFile, "param-file", "P", "", wski18n.T("`FILE` containing parameter values in JSON format"))
	actionUpdateCmd.Flags().StringVar(&Flags.action.web, WEB_FLAG, "", wski18n.T("treat ACTION as a web action, a raw HTTP web action, or as a standard action; yes | true = web action, raw = raw HTTP web action, no | false = standard action"))
	actionUpdateCmd.Flags().StringVar(&Flags.action.websecure, WEB_SECURE_FLAG, "", wski18n.T("secure the web action. where `SECRET` is true, false, or any string. Only valid when the ACTION is a web action"))
	actionUpdateCmd.Flags().StringArrayVar(&Flags.action.delAnnotation, "del-annotation", []string{}, wski18n.T("the list of annotations to be deleted from the action, e.g. --del-annotation key1 --del-annotation key2"))

	actionInvokeCmd.Flags().StringSliceVarP(&Flags.common.param, "param", "p", []string{}, wski18n.T("parameter values in `KEY VALUE` format"))
	actionInvokeCmd.Flags().StringVarP(&Flags.common.paramFile, "param-file", "P", "", wski18n.T("`FILE` containing parameter values in JSON format"))
	actionInvokeCmd.Flags().BoolVarP(&Flags.common.blocking, "blocking", "b", false, wski18n.T("blocking invoke"))
	actionInvokeCmd.Flags().BoolVarP(&Flags.action.result, "result", "r", false, wski18n.T("blocking invoke; show only activation result (unless there is a failure)"))

	actionGetCmd.Flags().BoolVarP(&Flags.common.summary, "summary", "s", false, wski18n.T("summarize action details; parameters with prefix \"*\" are bound, \"**\" are bound and finalized"))
	actionGetCmd.Flags().BoolVarP(&Flags.action.url, "url", "r", false, wski18n.T("get action url"))
	actionGetCmd.Flags().StringVar(&Flags.action.saveAs, SAVE_AS_FLAG, "", wski18n.T("file to save action code to"))
	actionGetCmd.Flags().BoolVarP(&Flags.action.save, SAVE_FLAG, "", false, wski18n.T("save action code to file corresponding with action name"))

	actionListCmd.Flags().IntVarP(&Flags.common.skip, "skip", "s", 0, wski18n.T("exclude the first `SKIP` number of actions from the result"))
	actionListCmd.Flags().IntVarP(&Flags.common.limit, "limit", "l", 30, wski18n.T("only return `LIMIT` number of actions from the collection"))
	actionListCmd.Flags().BoolVarP(&Flags.common.nameSort, "name-sort", "n", false, wski18n.T("sorts a list alphabetically by entity name; only applicable within the limit/skip returned entity block"))

	actionCmd.AddCommand(
		actionCreateCmd,
		actionUpdateCmd,
		actionInvokeCmd,
		actionGetCmd,
		actionDeleteCmd,
		actionListCmd,
	)
}
