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
	"errors"
	"fmt"
	"net/http"

	"github.com/apache/openwhisk-cli/wski18n"
	"github.com/apache/openwhisk-client-go/whisk"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const FEED_LIFECYCLE_EVENT = "lifecycleEvent"
const FEED_TRIGGER_NAME = "triggerName"
const FEED_AUTH_KEY = "authKey"
const FEED_CREATE = "CREATE"
const FEED_READ = "READ"
const FEED_UPDATE = "UPDATE"
const FEED_DELETE = "DELETE"

// triggerCmd represents the trigger command
var triggerCmd = &cobra.Command{
	Use:   "trigger",
	Short: wski18n.T("work with triggers"),
}

var trigger = Trigger{}

/**
 * Constructs the parameters to pass to the feed, consisting of the event type, trigger name, and subject key.
 *
 * NOTE: this function will exit in case of a processing error since it indicates a problem parsing parameters.
 *
 * @return the feed name and parameters if a feed is specified.
 */
func feedParameters(feed string, lifecycle string, trigger *QualifiedName, authKey string) (*QualifiedName, []string) {
	if feed == "" {
		return nil, make([]string, 0)
	}

	whisk.Debug(whisk.DbgInfo, "Trigger has a feed\n")

	var params []string
	name := fmt.Sprintf("/%s/%s", trigger.GetNamespace(), trigger.GetEntityName())
	params = append(params, getFormattedJSON(FEED_LIFECYCLE_EVENT, lifecycle))
	params = append(params, getFormattedJSON(FEED_TRIGGER_NAME, name))
	params = append(params, getFormattedJSON(FEED_AUTH_KEY, authKey))

	feedQualifiedName, err := NewQualifiedName(feed)
	if err != nil {
		ExitOnError(NewQualifiedNameError(feed, err))
	}

	return feedQualifiedName, params
}

/**
 * Create or update a trigger.
 *
 * NOTE: this function will exit in case of a processing error since it indicates a problem parsing parameters.
 */
func createOrUpdate(Client *whisk.Client, fqn *QualifiedName, trigger *whisk.Trigger, overwrite bool) {
	// TODO get rid of these global modifiers
	Client.Namespace = fqn.GetNamespace()
	_, _, err := Client.Triggers.Insert(trigger, overwrite)

	if err != nil {
		whisk.Debug(whisk.DbgError, "Client.Triggers.Insert(%+v, %t) failed: %s\n", trigger, overwrite, err)
		var errStr string
		if !overwrite {
			errStr = wski18n.T("Unable to create trigger '{{.name}}': {{.err}}",
				map[string]interface{}{"name": trigger.Name, "err": err})
		} else {
			errStr = wski18n.T("Unable to update trigger '{{.name}}': {{.err}}",
				map[string]interface{}{"name": trigger.Name, "err": err})
		}
		ExitOnError(whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE))
	}
}

var triggerFireCmd = &cobra.Command{
	Use:           "fire TRIGGER_NAME [PAYLOAD]",
	Short:         wski18n.T("fire trigger event"),
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE:       SetupClientConfig,
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error
		var qualifiedName = new(QualifiedName)

		if whiskErr := CheckArgs(args, 1, 1, "Trigger fire",
			wski18n.T("A trigger name is required.")); whiskErr != nil {
			return whiskErr
		}

		if qualifiedName, err = NewQualifiedName(args[0]); err != nil {
			return NewQualifiedNameError(args[0], err)
		}

		parameters := getParameters(Flags.common.param, false, false)

		// TODO get rid of these global modifiers
		Client.Namespace = qualifiedName.GetNamespace()

		trigResp, resp, err := Client.Triggers.Fire(qualifiedName.GetEntityName(), parameters)
		if err != nil {
			whisk.Debug(whisk.DbgError, "Client.Triggers.Fire(%s, %#v) failed: %s\n", qualifiedName.GetEntityName(), parameters, err)
			errStr := wski18n.T("Unable to fire trigger '{{.name}}': {{.err}}",
				map[string]interface{}{"name": qualifiedName.GetEntityName(), "err": err})
			werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL,
				whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
			return werr
		}

		if resp.StatusCode == http.StatusNoContent {
			fmt.Fprintf(color.Output,
				wski18n.T("trigger /{{.namespace}}/{{.name}} did not fire as it is not associated with an active rule\n",
					map[string]interface{}{
						"namespace": boldString(qualifiedName.GetNamespace()),
						"name":      boldString(qualifiedName.GetEntityName())}))

			return nil
		}

		fmt.Fprintf(color.Output,
			wski18n.T("{{.ok}} triggered /{{.namespace}}/{{.name}} with id {{.id}}\n",
				map[string]interface{}{
					"ok":        color.GreenString("ok:"),
					"namespace": boldString(qualifiedName.GetNamespace()),
					"name":      boldString(qualifiedName.GetEntityName()),
					"id":        boldString(trigResp.ActivationId)}))

		return nil
	},
}

var triggerCreateCmd = &cobra.Command{
	Use:           "create TRIGGER_NAME",
	Short:         wski18n.T("create new trigger"),
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE:       SetupClientConfig,
	RunE: func(cmd *cobra.Command, args []string) error {
		return trigger.Create(Client, args)
	},
}

var triggerUpdateCmd = &cobra.Command{
	Use:           "update TRIGGER_NAME",
	Short:         wski18n.T("update an existing trigger, or create a trigger if it does not exist"),
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE:       SetupClientConfig,
	RunE: func(cmd *cobra.Command, args []string) error {
		return trigger.Update(Client, args)
	},
}

var triggerGetCmd = &cobra.Command{
	Use:           "get TRIGGER_NAME [FIELD_FILTER]",
	Short:         wski18n.T("get trigger"),
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE:       SetupClientConfig,
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error
		var field string
		var fullFeedName string
		var qualifiedName = new(QualifiedName)

		if whiskErr := CheckArgs(args, 1, 2, "Trigger get", wski18n.T("A trigger name is required.")); whiskErr != nil {
			return whiskErr
		}

		if len(args) > 1 {
			field = args[1]

			if !fieldExists(&whisk.Trigger{}, field) {
				errMsg := wski18n.T("Invalid field filter '{{.arg}}'.", map[string]interface{}{"arg": field})
				whiskErr := whisk.MakeWskError(errors.New(errMsg), whisk.EXIT_CODE_ERR_GENERAL,
					whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
				return whiskErr
			}
		}

		if qualifiedName, err = NewQualifiedName(args[0]); err != nil {
			return NewQualifiedNameError(args[0], err)
		}

		Client.Namespace = qualifiedName.GetNamespace()
		retTrigger, _, err := Client.Triggers.Get(qualifiedName.GetEntityName())
		if err != nil {
			whisk.Debug(whisk.DbgError, "Client.Triggers.Get(%s) failed: %s\n", qualifiedName.GetEntityName(), err)
			errStr := wski18n.T("Unable to get trigger '{{.name}}': {{.err}}",
				map[string]interface{}{"name": qualifiedName.GetEntityName(), "err": err})
			werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
			return werr
		}

		// Get full feed name from trigger get request as it is needed to get the feed
		if retTrigger != nil && retTrigger.Annotations != nil {
			fullFeedName = getValueString(retTrigger.Annotations, "feed")
		}

		if len(fullFeedName) > 0 {
			fullTriggerName := fmt.Sprintf("/%s/%s", qualifiedName.GetNamespace(), qualifiedName.GetEntityName())
			Flags.common.param = append(Flags.common.param, getFormattedJSON(FEED_LIFECYCLE_EVENT, FEED_READ))
			Flags.common.param = append(Flags.common.param, getFormattedJSON(FEED_TRIGGER_NAME, fullTriggerName))
			Flags.common.param = append(Flags.common.param, getFormattedJSON(FEED_AUTH_KEY, Client.Config.AuthToken))

			err = configureFeed(qualifiedName.GetEntityName(), fullFeedName, getParameters(Flags.common.param, false, false))
			if err != nil {
				whisk.Debug(whisk.DbgError, "configureFeed(%s, %s) failed: %s\n", qualifiedName.GetEntityName(), fullFeedName, err)
			}
		} else {
			if Flags.trigger.summary {
				printSummary(retTrigger)
			} else {
				if len(field) > 0 {
					fmt.Fprintf(color.Output, wski18n.T("{{.ok}} got trigger {{.name}}, displaying field {{.field}}\n",
						map[string]interface{}{"ok": color.GreenString("ok:"), "name": boldString(qualifiedName.GetEntityName()),
							"field": boldString(field)}))
					printField(retTrigger, field)
				} else {
					fmt.Fprintf(color.Output, wski18n.T("{{.ok}} got trigger {{.name}}\n",
						map[string]interface{}{"ok": color.GreenString("ok:"), "name": boldString(qualifiedName.GetEntityName())}))
					printJSON(retTrigger)
				}
			}
		}

		return nil
	},
}

var triggerDeleteCmd = &cobra.Command{
	Use:           "delete TRIGGER_NAME",
	Short:         wski18n.T("delete trigger"),
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE:       SetupClientConfig,
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error
		var retTrigger *whisk.Trigger
		var fullFeedName string
		var origParams []string
		var qualifiedName = new(QualifiedName)

		if whiskErr := CheckArgs(args, 1, 1, "Trigger delete",
			wski18n.T("A trigger name is required.")); whiskErr != nil {
			return whiskErr
		}

		if qualifiedName, err = NewQualifiedName(args[0]); err != nil {
			return NewQualifiedNameError(args[0], err)
		}

		Client.Namespace = qualifiedName.GetNamespace()

		retTrigger, _, err = Client.Triggers.Get(qualifiedName.GetEntityName())
		if err != nil {
			whisk.Debug(whisk.DbgError, "Client.Triggers.Get(%s) failed: %s\n", qualifiedName.GetEntityName(), err)
			errStr := wski18n.T("Unable to get trigger '{{.name}}': {{.err}}",
				map[string]interface{}{"name": qualifiedName.GetEntityName(), "err": err})
			werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
			return werr
		}

		// Get full feed name from trigger delete request as it is needed to delete the feed
		if retTrigger != nil && retTrigger.Annotations != nil {
			fullFeedName = getValueString(retTrigger.Annotations, "feed")

			if len(fullFeedName) > 0 {
				origParams = Flags.common.param
				fullTriggerName := fmt.Sprintf("/%s/%s", qualifiedName.GetNamespace(), qualifiedName.GetEntityName())
				Flags.common.param = append(Flags.common.param, getFormattedJSON(FEED_LIFECYCLE_EVENT, FEED_DELETE))
				Flags.common.param = append(Flags.common.param, getFormattedJSON(FEED_TRIGGER_NAME, fullTriggerName))
				Flags.common.param = append(Flags.common.param, getFormattedJSON(FEED_AUTH_KEY, Client.Config.AuthToken))

				err = configureFeed(qualifiedName.GetEntityName(), fullFeedName, getParameters(Flags.common.param, false, false))
				if err != nil {
					whisk.Debug(whisk.DbgError, "configureFeed(%s, %s) failed: %s\n", qualifiedName.GetEntityName(), fullFeedName, err)
				}

				Flags.common.param = origParams
				Client.Namespace = qualifiedName.GetNamespace()
			}
		}

		retTrigger, _, err = Client.Triggers.Delete(qualifiedName.GetEntityName())
		if err != nil {
			whisk.Debug(whisk.DbgError, "Client.Triggers.Delete(%s) failed: %s\n", qualifiedName.GetEntityName(), err)
			errStr := wski18n.T("Unable to delete trigger '{{.name}}': {{.err}}",
				map[string]interface{}{"name": qualifiedName.GetEntityName(), "err": err})
			werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
			return werr
		}

		fmt.Fprintf(color.Output,
			wski18n.T("{{.ok}} deleted trigger {{.name}}\n",
				map[string]interface{}{"ok": color.GreenString("ok:"), "name": boldString(qualifiedName.GetEntityName())}))

		return nil
	},
}

var triggerListCmd = &cobra.Command{
	Use:           "list [NAMESPACE]",
	Short:         wski18n.T("list all triggers"),
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE:       SetupClientConfig,
	RunE: func(cmd *cobra.Command, args []string) error {
		var err error
		var qualifiedName = new(QualifiedName)

		if whiskErr := CheckArgs(args, 0, 1, "Trigger list",
			wski18n.T("An optional namespace is the only valid argument.")); whiskErr != nil {
			return whiskErr
		}

		if len(args) == 1 {
			if qualifiedName, err = NewQualifiedName(args[0]); err != nil {
				return NewQualifiedNameError(args[0], err)
			}

			if len(qualifiedName.GetEntityName()) > 0 {
				return entityNameError(qualifiedName.GetEntityName())
			}

			Client.Namespace = qualifiedName.GetNamespace()
		}

		options := &whisk.TriggerListOptions{
			Skip:  Flags.common.skip,
			Limit: Flags.common.limit,
		}
		triggers, _, err := Client.Triggers.List(options)
		if err != nil {
			whisk.Debug(whisk.DbgError, "Client.Triggers.List(%#v) for namespace '%s' failed: %s\n", options,
				Client.Namespace, err)
			errStr := wski18n.T("Unable to obtain the list of triggers for namespace '{{.name}}': {{.err}}",
				map[string]interface{}{"name": getClientNamespace(), "err": err})
			werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
			return werr
		}
		sortByName := Flags.common.nameSort
		printList(triggers, sortByName)
		return nil
	},
}

func configureFeed(triggerName string, feedName string, parameters interface{}) error {
	var fullFeedName *QualifiedName
	var err error

	if fullFeedName, err = NewQualifiedName(feedName); err != nil {
		return NewQualifiedNameError(feedName, err)
	}

	res, err := invokeAction(*fullFeedName, parameters, true, false)
	err = printInvocationResponse(*fullFeedName, true, false, res, err)

	if err != nil {
		whisk.Debug(whisk.DbgError, "Invoke of action '%s' failed: %s\n", feedName, err)
		errStr := wski18n.T(FEED_CONFIGURATION_FAILURE, map[string]interface{}{"feedname": feedName, "trigname": triggerName, "err": err})
		err = whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
	} else {
		whisk.Debug(whisk.DbgInfo, "Successfully configured trigger feed via feed action '%s'\n", feedName)
	}

	return err
}

func deleteTrigger(triggerName string) error {
	args := []string{triggerName}
	err := triggerDeleteCmd.RunE(nil, args)
	if err != nil {
		whisk.Debug(whisk.DbgError, "Trigger '%s' delete failed: %s\n", triggerName, err)
		errStr := wski18n.T("Unable to delete trigger '{{.name}}': {{.err}}",
			map[string]interface{}{"name": triggerName, "err": err})
		err = whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
	}

	return err
}

func init() {
	triggerCreateCmd.Flags().StringSliceVarP(&Flags.common.annotation, "annotation", "a", []string{}, wski18n.T("annotation values in `KEY VALUE` format"))
	triggerCreateCmd.Flags().StringVarP(&Flags.common.annotFile, "annotation-file", "A", "", wski18n.T("`FILE` containing annotation values in JSON format"))
	triggerCreateCmd.Flags().StringSliceVarP(&Flags.common.param, "param", "p", []string{}, wski18n.T("parameter values in `KEY VALUE` format"))
	triggerCreateCmd.Flags().StringVarP(&Flags.common.paramFile, "param-file", "P", "", wski18n.T("`FILE` containing parameter values in JSON format"))
	triggerCreateCmd.Flags().StringVarP(&Flags.common.feed, "feed", "f", "", wski18n.T("trigger feed `ACTION_NAME`"))
	triggerCreateCmd.Flags().StringSliceVarP(&Flags.trigger.feedParam, "feed-param", "F", []string{}, wski18n.T("feed parameter values in `KEY VALUE` format"))
	triggerCreateCmd.Flags().StringSliceVarP(&Flags.trigger.triggerParam, "trigger-param", "T", []string{}, wski18n.T("trigger parameter values in `KEY VALUE` format"))

	triggerUpdateCmd.Flags().StringSliceVarP(&Flags.common.annotation, "annotation", "a", []string{}, wski18n.T("annotation values in `KEY VALUE` format"))
	triggerUpdateCmd.Flags().StringVarP(&Flags.common.annotFile, "annotation-file", "A", "", wski18n.T("`FILE` containing annotation values in JSON format"))
	triggerUpdateCmd.Flags().StringSliceVarP(&Flags.common.param, "param", "p", []string{}, wski18n.T("parameter values in `KEY VALUE` format"))
	triggerUpdateCmd.Flags().StringVarP(&Flags.common.paramFile, "param-file", "P", "", wski18n.T("`FILE` containing parameter values in JSON format"))
	triggerUpdateCmd.Flags().StringSliceVarP(&Flags.trigger.feedParam, "feed-param", "F", []string{}, wski18n.T("feed parameter values in `KEY VALUE` format"))
	triggerUpdateCmd.Flags().StringSliceVarP(&Flags.trigger.triggerParam, "trigger-param", "T", []string{}, wski18n.T("trigger parameter values in `KEY VALUE` format"))

	triggerGetCmd.Flags().BoolVarP(&Flags.trigger.summary, "summary", "s", false, wski18n.T("summarize trigger details; parameters with prefix \"*\" are bound"))

	triggerFireCmd.Flags().StringSliceVarP(&Flags.common.param, "param", "p", []string{}, wski18n.T("parameter values in `KEY VALUE` format"))
	triggerFireCmd.Flags().StringVarP(&Flags.common.paramFile, "param-file", "P", "", wski18n.T("`FILE` containing parameter values in JSON format"))

	triggerListCmd.Flags().IntVarP(&Flags.common.skip, "skip", "s", 0, wski18n.T("exclude the first `SKIP` number of triggers from the result"))
	triggerListCmd.Flags().IntVarP(&Flags.common.limit, "limit", "l", 30, wski18n.T("only return `LIMIT` number of triggers from the collection"))
	triggerListCmd.Flags().BoolVarP(&Flags.common.nameSort, "name-sort", "n", false, wski18n.T("sorts a list alphabetically by entity name; only applicable within the limit/skip returned entity block"))

	triggerCmd.AddCommand(
		triggerFireCmd,
		triggerCreateCmd,
		triggerUpdateCmd,
		triggerGetCmd,
		triggerDeleteCmd,
		triggerListCmd,
	)
}

type Trigger struct {
}

func (t *Trigger) Create(Client *whisk.Client, args []string) error {
	if whiskErr := CheckArgs(args, 1, 1, "Trigger create",
		wski18n.T("A trigger name is required.")); whiskErr != nil {
		return whiskErr
	}

	//1. if the command line arguments user provides contains only --param flags
	//2. if the command line arguments user provides contains no --param flags at all
	//we should process the trigger create command in the old way.
	if userIndicatesToUseOldTriggerCommand() {
		triggerName, err := NewQualifiedName(args[0])
		if err != nil {
			return NewQualifiedNameError(args[0], err)
		}

		//if user also issued new trigger command then we stop execution
		if triggerUsageErr := userIssuedNewTriggerCmd(); triggerUsageErr != nil {
			return triggerUsageErr
		}

		annotationArray := Flags.common.annotation
		authToken := Client.Config.AuthToken

		// if a feed is specified, create additional parameters which must be passed to the feed
		feedQualifiedName, additionalFeedParams := feedParameters(Flags.common.feed, FEED_CREATE, triggerName, authToken)

		// if a feed is specified, add feed annotation the annotations declared on the command line
		// TODO: add test to ensure that generated annotation has precedence
		if feedQualifiedName != nil {
			annotationArray = append(annotationArray, getFormattedJSON("feed", feedQualifiedName.GetFullQualifiedName()))
		}
		annotations := getParameters(annotationArray, true, true)

		// the feed receives all the parameters that are specified on the command line so we merge
		// the feed lifecycle parameters with the command line ones
		parameters := getParameters(append(Flags.common.param, additionalFeedParams...), feedQualifiedName == nil, false)

		trigger := &whisk.Trigger{
			Name:        triggerName.GetEntityName(),
			Annotations: annotations.(whisk.KeyValueArr),
		}

		if feedQualifiedName == nil {
			// parameters are only attached to the trigger in there is no feed, otherwise
			// parameters are passed to the feed instead
			trigger.Parameters = parameters.(whisk.KeyValueArr)
		}

		createOrUpdate(Client, triggerName, trigger, false)

		// Invoke the specified feed action to configure the trigger feed
		if feedQualifiedName != nil {
			res, err := invokeAction(*feedQualifiedName, parameters, true, false)
			if err != nil {
				whisk.Debug(whisk.DbgError, "Failed configuring feed '%s' failed: %s\n", feedQualifiedName.GetFullQualifiedName(), err)

				// TODO: should we do this at all? Keeping for now.
				printFailedBlockingInvocationResponse(*feedQualifiedName, false, res, err)

				reason := wski18n.T(FEED_CONFIGURATION_FAILURE, map[string]interface{}{"feedname": feedQualifiedName.GetFullQualifiedName(), "err": err})
				errStr := wski18n.T("Unable to create trigger '{{.name}}': {{.err}}",
					map[string]interface{}{"name": trigger.Name, "err": reason})
				werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)

				// Delete trigger that was created for this feed
				err = deleteTrigger(triggerName.GetEntityName())
				if err != nil {
					whisk.Debug(whisk.DbgWarn, "Ignoring deleteTrigger(%s) failure: %s\n", triggerName.GetEntityName(), err)
				}

				return werr
			} else {
				whisk.Debug(whisk.DbgInfo, "Successfully configured trigger feed via feed action '%s'\n", Flags.common.feed)

				// preserve existing behavior where output of feed activation is emitted to console
				printInvocationMsg(*feedQualifiedName, true, true, res, color.Output)
			}
		}

		fmt.Fprintf(color.Output,
			wski18n.T("{{.ok}} created trigger {{.name}}\n",
				map[string]interface{}{"ok": color.GreenString("ok:"), "name": boldString(trigger.Name)}))
		return nil
	}
	//1. if user's input command line argument contains either --feed-param or --trigger-param
	//2. if user's input command line argument contains both --feed-param and --trigger-param
	//then we process trigger create command in a different way
	return CreateExtendedVersion(Client, args)
}

//CreateExtendedVersion only executes when users indicate to create triggers with --feed-param
//or --trigger-param flags.
func CreateExtendedVersion(Client *whisk.Client, args []string) error {
	triggerName, err := NewQualifiedName(args[0])
	if err != nil {
		return NewQualifiedNameError(args[0], err)
	}

	annotationArray := Flags.common.annotation
	authToken := Client.Config.AuthToken

	// if a feed is specified, create additional parameters which must be passed to the feed
	feedQualifiedName, additionalFeedParams := feedParameters(Flags.common.feed, FEED_CREATE, triggerName, authToken)

	// if a feed is specified, add feed annotation the annotations declared on the command line
	// TODO: add test to ensure that generated annotation has precedence
	if feedQualifiedName != nil {
		annotationArray = append(annotationArray, getFormattedJSON("feed", feedQualifiedName.GetFullQualifiedName()))
	}

	annotations := getParameters(annotationArray, true, true)

	//if trigger contains no feed but user tries to update feed parameter, then we issue error.
	if feedQualifiedName == nil && len(Flags.trigger.feedParam) > 0 {
		errStr := wski18n.T("Incorrect usage. Trigger without a feed cannot have feed parameters")
		return whisk.MakeWskError(errors.New(errStr), whisk.NOT_ALLOWED, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
	}

	triggerParams := getParameters(Flags.trigger.triggerParam, true, false)
	//if a feed is specified, add feed annotation the annotations declared on the command line
	//TODO: add test to ensure that generated annotation has precedence
	feedParams := getParameters(append(Flags.trigger.feedParam, additionalFeedParams...), feedQualifiedName == nil, false)

	trigger := &whisk.Trigger{
		Name:        triggerName.GetEntityName(),
		Annotations: annotations.(whisk.KeyValueArr),
		Parameters:  triggerParams.(whisk.KeyValueArr),
	}

	createOrUpdate(Client, triggerName, trigger, false)
	// Invoke the specified feed action to configure the trigger feed
	if feedQualifiedName != nil {
		res, err := invokeAction(*feedQualifiedName, feedParams, true, false)
		if err != nil {
			whisk.Debug(whisk.DbgError, "Failed configuring feed '%s' failed: %s\n", feedQualifiedName.GetFullQualifiedName(), err)

			// TODO: should we do this at all? Keeping for now.
			printFailedBlockingInvocationResponse(*feedQualifiedName, false, res, err)

			reason := wski18n.T(FEED_CONFIGURATION_FAILURE, map[string]interface{}{"feedname": feedQualifiedName.GetFullQualifiedName(), "err": err})
			errStr := wski18n.T("Unable to create trigger '{{.name}}': {{.err}}",
				map[string]interface{}{"name": trigger.Name, "err": reason})
			werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)

			// Delete trigger that was created for this feed
			err = deleteTrigger(triggerName.GetEntityName())
			if err != nil {
				whisk.Debug(whisk.DbgWarn, "Ignoring deleteTrigger(%s) failure: %s\n", triggerName.GetEntityName(), err)
			}

			return werr
		}
		whisk.Debug(whisk.DbgInfo, "Successfully configured trigger feed via feed action '%s'\n", Flags.common.feed)
		// preserve existing behavior where output of feed activation is emitted to console
		printInvocationMsg(*feedQualifiedName, true, true, res, color.Output)

	}

	fmt.Fprintf(color.Output,
		wski18n.T("{{.ok}} created trigger {{.name}}\n",
			map[string]interface{}{"ok": color.GreenString("ok:"), "name": boldString(trigger.Name)}))

	return nil
}

func (t *Trigger) Update(Client *whisk.Client, args []string) error {
	var err error
	var fullFeedName string
	var qualifiedName = new(QualifiedName)

	if whiskErr := CheckArgs(args, 1, 1, "Trigger update",
		wski18n.T("A trigger name is required.")); whiskErr != nil {
		return whiskErr
	}

	if qualifiedName, err = NewQualifiedName(args[0]); err != nil {
		return NewQualifiedNameError(args[0], err)
	}

	Client.Namespace = qualifiedName.GetNamespace()

	// Convert the trigger's list of default parameters from a string into []KeyValue
	// The 1 or more --param arguments have all been combined into a single []string
	// e.g.   --p arg1,arg2 --p arg3,arg4   ->  [arg1, arg2, arg3, arg4]

	whisk.Debug(whisk.DbgInfo, "Parsing parameters: %#v\n", Flags.common.param)
	parameters, err := getJSONFromStrings(Flags.common.param, true)

	if err != nil {
		whisk.Debug(whisk.DbgError, "getJSONFromStrings(%#v, true) failed: %s\n", Flags.common.param, err)
		errStr := wski18n.T("Invalid parameter argument '{{.param}}': {{.err}}",
			map[string]interface{}{"param": fmt.Sprintf("%#v", Flags.common.param), "err": err})
		werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
		return werr
	}

	whisk.Debug(whisk.DbgInfo, "Parsing annotations: %#v\n", Flags.common.annotation)
	annotations, err := getJSONFromStrings(Flags.common.annotation, true)

	if err != nil {
		whisk.Debug(whisk.DbgError, "getJSONFromStrings(%#v, true) failed: %s\n", Flags.common.annotation, err)
		errStr := wski18n.T("Invalid annotation argument '{{.annotation}}': {{.err}}",
			map[string]interface{}{"annotation": fmt.Sprintf("%#v", Flags.common.annotation), "err": err})
		werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
		return werr
	}

	retTrigger, httpResp, err := Client.Triggers.Get(qualifiedName.GetEntityName())

	if err != nil && httpResp.StatusCode == 404 {
		if createErr := t.Create(Client, args); createErr != nil {
			return createErr
		}
		return nil
	} else if err != nil {
		whisk.Debug(whisk.DbgError, "Client.Triggers.Get(%s) failed: %s\n", qualifiedName.GetEntityName(), err)
		errStr := wski18n.T("Unable to get trigger '{{.name}}': {{.err}}",
			map[string]interface{}{"name": qualifiedName.GetEntityName(), "err": err})
		werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
		return werr
	} else {
		if !userIndicatesToUseOldTriggerCommand() {
			return UpdateExtendedVersion(Client, args, retTrigger)
		}

		if triggerUsageErr := userIssuedNewTriggerCmd(); triggerUsageErr != nil {
			return triggerUsageErr
		}
		// Get full feed name from trigger get request as it is needed to get the feed
		if retTrigger != nil && retTrigger.Annotations != nil {
			fullFeedName = getValueString(retTrigger.Annotations, "feed")
		}

		if len(fullFeedName) > 0 {
			fullTriggerName := fmt.Sprintf("/%s/%s", qualifiedName.GetNamespace(), qualifiedName.GetEntityName())
			Flags.common.param = append(Flags.common.param, getFormattedJSON(FEED_LIFECYCLE_EVENT, FEED_UPDATE))
			Flags.common.param = append(Flags.common.param, getFormattedJSON(FEED_TRIGGER_NAME, fullTriggerName))
			Flags.common.param = append(Flags.common.param, getFormattedJSON(FEED_AUTH_KEY, Client.Config.AuthToken))

			// Invoke the specified feed action to configure the trigger feed
			err = configureFeed(qualifiedName.GetEntityName(), fullFeedName, getParameters(Flags.common.param, false, false))
			if err != nil {
				whisk.Debug(whisk.DbgError, "configureFeed(%s, %s) failed: %s\n", qualifiedName.GetEntityName(), Flags.common.feed,
					err)
				errStr := wski18n.T("Unable to create trigger '{{.name}}': {{.err}}",
					map[string]interface{}{"name": qualifiedName.GetEntityName(), "err": err})
				werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
				return werr
			}
		} else {
			trigger := &whisk.Trigger{
				Name:        qualifiedName.GetEntityName(),
				Parameters:  parameters.(whisk.KeyValueArr),
				Annotations: annotations.(whisk.KeyValueArr),
			}

			_, _, err = Client.Triggers.Insert(trigger, true)
			if err != nil {
				whisk.Debug(whisk.DbgError, "Client.Triggers.Insert(%+v,true) failed: %s\n", trigger, err)
				errStr := wski18n.T("Unable to update trigger '{{.name}}': {{.err}}",
					map[string]interface{}{"name": trigger.Name, "err": err})
				werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
				return werr
			}
		}

		fmt.Fprintf(color.Output,
			wski18n.T("{{.ok}} updated trigger {{.name}}\n",
				map[string]interface{}{"ok": color.GreenString("ok:"), "name": boldString(qualifiedName.GetEntityName())}))
	}

	return nil
}

//UpdateExtendedVersion only executes when users indicate to update triggers with --feed-param
//or --trigger-param flags.
func UpdateExtendedVersion(Client *whisk.Client, args []string, retTrigger *whisk.Trigger) error {
	var fullFeedName string
	var qualifiedName = new(QualifiedName)
	var err error

	if qualifiedName, err = NewQualifiedName(args[0]); err != nil {
		return NewQualifiedNameError(args[0], err)
	}

	whisk.Debug(whisk.DbgInfo, "Parsing parameters: %#v\n", Flags.trigger.triggerParam)
	triggerParameters, err := getJSONFromStrings(Flags.trigger.triggerParam, true)
	if err != nil {
		whisk.Debug(whisk.DbgError, "getJSONFromStrings(%#v, true) failed: %s\n", Flags.common.param, err)
		errStr := wski18n.T("Invalid parameter argument '{{.param}}': {{.err}}",
			map[string]interface{}{"param": fmt.Sprintf("%#v", Flags.common.param), "err": err})
		werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
		return werr
	}

	whisk.Debug(whisk.DbgInfo, "Parsing annotations: %#v\n", Flags.common.annotation)
	annotations, err := getJSONFromStrings(Flags.common.annotation, true)
	if err != nil {
		whisk.Debug(whisk.DbgError, "getJSONFromStrings(%#v, true) failed: %s\n", Flags.common.annotation, err)
		errStr := wski18n.T("Invalid annotation argument '{{.annotation}}': {{.err}}",
			map[string]interface{}{"annotation": fmt.Sprintf("%#v", Flags.common.annotation), "err": err})
		werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
		return werr
	}

	trigger := &whisk.Trigger{
		Name:        qualifiedName.GetEntityName(),
		Parameters:  triggerParameters.(whisk.KeyValueArr),
		Annotations: annotations.(whisk.KeyValueArr),
	}

	// Get full feed name from trigger get request as it is needed to get the feed
	if retTrigger != nil && retTrigger.Annotations != nil {
		fullFeedName = getValueString(retTrigger.Annotations, "feed")
	}

	_, _, err = Client.Triggers.Insert(trigger, true)
	if err != nil {
		whisk.Debug(whisk.DbgError, "Client.Triggers.Insert(%+v,true) failed: %s\n", trigger, err)
		errStr := wski18n.T("Unable to update trigger '{{.name}}': {{.err}}",
			map[string]interface{}{"name": trigger.Name, "err": err})
		werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
		return werr
	}
	//if there is no feed attached to this trigger
	if len(fullFeedName) < 1 {
		//but user indicate feed parameter change, we issue error message.
		if len(Flags.trigger.feedParam) > 0 {
			whisk.Debug(whisk.DbgError, "trigger %+v is found but it does not contain a feed. \n", trigger)
			err := errors.New("this trigger does not contain a feed")
			errStr := wski18n.T(FEED_CONFIGURATION_FAILURE, map[string]interface{}{"feedname": qualifiedName.GetEntityName(), "err": err})
			werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
			return werr
		}
	}

	if len(fullFeedName) > 0 && feedParameterChanged(Flags.trigger.feedParam) {
		//if there is feed, we invoke the action to configure the feed regardless any changes on feed parameters
		fullTriggerName := fmt.Sprintf("/%s/%s", qualifiedName.GetNamespace(), qualifiedName.GetEntityName())
		Flags.trigger.feedParam = append(Flags.trigger.feedParam, getFormattedJSON(FEED_LIFECYCLE_EVENT, FEED_UPDATE))
		Flags.trigger.feedParam = append(Flags.trigger.feedParam, getFormattedJSON(FEED_TRIGGER_NAME, fullTriggerName))
		Flags.trigger.feedParam = append(Flags.trigger.feedParam, getFormattedJSON(FEED_AUTH_KEY, Client.Config.AuthToken))

		// Invoke the specified feed action to configure the trigger feed
		err = configureFeed(qualifiedName.GetEntityName(), fullFeedName, getParameters(Flags.trigger.feedParam, false, false))
		if err != nil {
			whisk.Debug(whisk.DbgError, "configureFeed(%s, %s) failed: %s\n", qualifiedName.GetEntityName(), Flags.common.feed, err)
			errStr := wski18n.T("Unable to create trigger '{{.name}}': {{.err}}",
				map[string]interface{}{"name": qualifiedName.GetEntityName(), "err": err})
			werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
			return werr
		}
	}

	fmt.Fprintf(color.Output,
		wski18n.T("{{.ok}} updated trigger {{.name}}\n",
			map[string]interface{}{"ok": color.GreenString("ok:"), "name": boldString(qualifiedName.GetEntityName())}))

	return nil
}

func feedParameterChanged(triggerParam []string) bool {
	return len(triggerParam) > 0
}

//if users are 1. creating a trigger without any feed or parameters
//             2. creating a trigger using --param flag
//then we use the old way to create the trigger.
func userIndicatesToUseOldTriggerCommand() bool {
	return len(Flags.common.param) > 0 || (len(Flags.trigger.feedParam) == 0 && len(Flags.common.param) == 0 && len(Flags.trigger.triggerParam) == 0)
}

func userIssuedNewTriggerCmd() error {
	if len(Flags.trigger.feedParam) > 0 || len(Flags.trigger.triggerParam) > 0 {
		whisk.Debug(whisk.DbgError, "User tries to mix use of --param or --param-file flags with --feed-param or --trigger-param")
		errStr := wski18n.T("Incorrect usage. Cannot combine --feed-param or --trigger-param flag with neither --param nor --param-file flag")
		return whisk.MakeWskError(errors.New(errStr), whisk.NOT_ALLOWED, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
	}
	return nil
}
