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
	"os"

	"github.com/fatih/color"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"

	"github.com/apache/incubator-openwhisk-cli/wski18n"
	"github.com/apache/incubator-openwhisk-client-go/whisk"
)

var Properties struct {
	Cert       string
	Key        string
	CaCert     string
	Auth       string
	APIHost    string
	APIVersion string
	APIBuild   string
	APIBuildNo string
	CLIVersion string
	Namespace  string
	PropsFile  string
}

const DefaultCert string = ""
const DefaultKey string = ""
const DefaultCaCert string = ""
const DefaultAuth string = ""
const DefaultAPIHost string = ""
const DefaultAPIVersion string = "v1"
const DefaultAPIBuild string = ""
const DefaultAPIBuildNo string = ""
const DefaultNamespace string = "_"
const DefaultPropsFile string = "~/.wskprops"

var propertyCmd = &cobra.Command{
	Use:   "property",
	Short: wski18n.T("work with whisk properties"),
}

//
// Set one or more openwhisk property values
//
var propertySetCmd = &cobra.Command{
	Use:           "set",
	Short:         wski18n.T("set property"),
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE:       SetupClientConfig,
	RunE: func(cmd *cobra.Command, args []string) error {
		var okMsg string = ""
		var werr *whisk.WskError = nil

		// get current props
		props, err := ReadProps(Properties.PropsFile)
		if err != nil {
			whisk.Debug(whisk.DbgError, "readProps(%s) failed: %s\n", Properties.PropsFile, err)
			errStr := wski18n.T("Unable to set the property value: {{.err}}", map[string]interface{}{"err": err})
			werr = whisk.MakeWskError(errors.New(errStr), whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
			return werr
		}

		// read in each flag, update if necessary
		if cert := Flags.Global.Cert; len(cert) > 0 {
			props["CERT"] = cert
			Client.Config.Cert = cert
			okMsg += fmt.Sprintf(
				wski18n.T("{{.ok}} client cert set. Run 'wsk property get --cert' to see the new value.\n",
					map[string]interface{}{"ok": color.GreenString("ok:")}))
		}

		if key := Flags.Global.Key; len(key) > 0 {
			props["KEY"] = key
			Client.Config.Key = key
			okMsg += fmt.Sprintf(
				wski18n.T("{{.ok}} client key set. Run 'wsk property get --key' to see the new value.\n",
					map[string]interface{}{"ok": color.GreenString("ok:")}))
		}

		if key := Flags.Global.CaCert; len(key) > 0 {
			props["CACERT"] = key
			Client.Config.CaCert = key
			okMsg += fmt.Sprintf(
				wski18n.T("{{.ok}} CA cert set. Run 'wsk property get --cacert' to see the new value.\n",
					map[string]interface{}{"ok": color.GreenString("ok:")}))
		}

		if auth := Flags.Global.Auth; len(auth) > 0 {
			props["AUTH"] = auth
			Client.Config.AuthToken = auth
			okMsg += fmt.Sprintf(
				wski18n.T("{{.ok}} whisk auth set. Run 'wsk property get --auth' to see the new value.\n",
					map[string]interface{}{"ok": color.GreenString("ok:")}))
		}

		if apiHost := Flags.property.apihostSet; len(apiHost) > 0 {
			baseURL, err := whisk.GetURLBase(apiHost, DefaultOpenWhiskApiPath)

			if err != nil {
				// Not aborting now.  Subsequent commands will result in error
				whisk.Debug(whisk.DbgError, "whisk.GetURLBase(%s, %s) error: %s", apiHost, DefaultOpenWhiskApiPath, err)
				errStr := fmt.Sprintf(
					wski18n.T("Unable to set API host value; the API host value '{{.apihost}}' is invalid: {{.err}}",
						map[string]interface{}{"apihost": apiHost, "err": err}))
				werr = whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL,
					whisk.DISPLAY_MSG, whisk.DISPLAY_USAGE)
			} else {
				props["APIHOST"] = apiHost
				Client.Config.BaseURL = baseURL
				okMsg += fmt.Sprintf(
					wski18n.T("{{.ok}} whisk API host set to {{.host}}\n",
						map[string]interface{}{"ok": color.GreenString("ok:"), "host": boldString(apiHost)}))
			}
		}

		if apiVersion := Flags.property.apiversionSet; len(apiVersion) > 0 {
			props["APIVERSION"] = apiVersion
			Client.Config.Version = apiVersion
			okMsg += fmt.Sprintf(
				wski18n.T("{{.ok}} whisk API version set to {{.version}}\n",
					map[string]interface{}{"ok": color.GreenString("ok:"), "version": boldString(apiVersion)}))
		}

		if namespace := Flags.property.namespaceSet; len(namespace) > 0 {
			namespaces, _, err := Client.Namespaces.List()
			if err != nil {
				whisk.Debug(whisk.DbgError, "Client.Namespaces.List() failed: %s\n", err)
				errStr := fmt.Sprintf(
					wski18n.T("Authenticated user does not have namespace '{{.name}}'; set command failed: {{.err}}",
						map[string]interface{}{"name": namespace, "err": err}))
				werr = whisk.MakeWskError(errors.New(errStr), whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
			} else {
				whisk.Debug(whisk.DbgInfo, "Validating namespace '%s' is in user namespace list %#v\n", namespace, namespaces)
				var validNamespace bool
				for _, ns := range namespaces {
					if ns.Name == namespace {
						whisk.Debug(whisk.DbgInfo, "Namespace '%s' is valid\n", namespace)
						validNamespace = true
					}
				}
				if !validNamespace {
					whisk.Debug(whisk.DbgError, "Namespace '%s' is not in the list of entitled namespaces\n", namespace)
					errStr := fmt.Sprintf(
						wski18n.T("Namespace '{{.name}}' is not in the list of entitled namespaces",
							map[string]interface{}{"name": namespace}))
					werr = whisk.MakeWskError(errors.New(errStr), whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
				} else {
					props["NAMESPACE"] = namespace
					okMsg += fmt.Sprintf(
						wski18n.T("{{.ok}} whisk namespace set to {{.name}}\n",
							map[string]interface{}{"ok": color.GreenString("ok:"), "name": boldString(namespace)}))
				}
			}
		}

		err = WriteProps(Properties.PropsFile, props)
		if err != nil {
			whisk.Debug(whisk.DbgError, "writeProps(%s, %#v) failed: %s\n", Properties.PropsFile, props, err)
			errStr := fmt.Sprintf(
				wski18n.T("Unable to set the property value(s): {{.err}}",
					map[string]interface{}{"err": err}))
			werr = whisk.MakeWskError(errors.New(errStr), whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
		} else {
			fmt.Fprintf(color.Output, okMsg)
		}

		if werr != nil {
			return werr
		}

		return nil
	},
}

var propertyUnsetCmd = &cobra.Command{
	Use:           "unset",
	Short:         wski18n.T("unset property"),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		var okMsg string = ""
		props, err := ReadProps(Properties.PropsFile)
		if err != nil {
			whisk.Debug(whisk.DbgError, "readProps(%s) failed: %s\n", Properties.PropsFile, err)
			errStr := fmt.Sprintf(
				wski18n.T("Unable to unset the property value: {{.err}}",
					map[string]interface{}{"err": err}))
			werr := whisk.MakeWskError(errors.New(errStr), whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
			return werr
		}

		// read in each flag, update if necessary

		if Flags.property.cert {
			delete(props, "CERT")
			okMsg += fmt.Sprintf(
				wski18n.T("{{.ok}} client cert unset.\n",
					map[string]interface{}{"ok": color.GreenString("ok:")}))
		}

		if Flags.property.key {
			delete(props, "KEY")
			okMsg += fmt.Sprintf(
				wski18n.T("{{.ok}} client key unset.\n",
					map[string]interface{}{"ok": color.GreenString("ok:")}))
		}

		if Flags.property.cacert {
			delete(props, "CACERT")
			okMsg += fmt.Sprintf(
				wski18n.T("{{.ok}} CA cert unset.\n",
					map[string]interface{}{"ok": color.GreenString("ok:")}))
		}

		if Flags.property.auth {
			delete(props, "AUTH")
			okMsg += fmt.Sprintf(
				wski18n.T("{{.ok}} whisk auth unset.\n",
					map[string]interface{}{"ok": color.GreenString("ok:")}))
		}

		if Flags.property.namespace {
			delete(props, "NAMESPACE")
			okMsg += fmt.Sprintf(
				wski18n.T("{{.ok}} whisk namespace unset",
					map[string]interface{}{"ok": color.GreenString("ok:")}))
			if len(DefaultNamespace) > 0 {
				okMsg += fmt.Sprintf(
					wski18n.T("; the default value of {{.default}} will be used.\n",
						map[string]interface{}{"default": boldString(DefaultNamespace)}))
			} else {
				okMsg += fmt.Sprint(
					wski18n.T("; there is no default value that can be used.\n"))
			}
		}

		if Flags.property.apihost {
			delete(props, "APIHOST")
			okMsg += fmt.Sprintf(
				wski18n.T("{{.ok}} whisk API host unset.\n",
					map[string]interface{}{"ok": color.GreenString("ok:")}))
		}

		if Flags.property.apiversion {
			delete(props, "APIVERSION")
			okMsg += fmt.Sprintf(
				wski18n.T("{{.ok}} whisk API version unset",
					map[string]interface{}{"ok": color.GreenString("ok:")}))
			if len(DefaultAPIVersion) > 0 {
				okMsg += fmt.Sprintf(
					wski18n.T("; the default value of {{.default}} will be used.\n",
						map[string]interface{}{"default": boldString(DefaultAPIVersion)}))
			} else {
				okMsg += fmt.Sprint(
					wski18n.T("; there is no default value that can be used.\n"))
			}
		}

		err = WriteProps(Properties.PropsFile, props)
		if err != nil {
			whisk.Debug(whisk.DbgError, "writeProps(%s, %#v) failed: %s\n", Properties.PropsFile, props, err)
			errStr := fmt.Sprintf(
				wski18n.T("Unable to unset the property value: {{.err}}",
					map[string]interface{}{"err": err}))
			werr := whisk.MakeWskError(errors.New(errStr), whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
			return werr
		}

		fmt.Fprintf(color.Output, okMsg)
		if err = loadProperties(); err != nil {
			whisk.Debug(whisk.DbgError, "loadProperties() failed: %s\n", err)
		}
		return nil
	},
}

var propertyGetCmd = &cobra.Command{
	Use:           "get",
	Short:         wski18n.T("get property"),
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE:       SetupClientConfig,
	RunE: func(cmd *cobra.Command, args []string) error {

		// If no property is explicitly specified, default to all properties
		if !(Flags.property.all || Flags.property.cert ||
			Flags.property.key || Flags.property.cacert ||
			Flags.property.auth ||
			Flags.property.apiversion || Flags.property.cliversion ||
			Flags.property.namespace || Flags.property.apibuild ||
			Flags.property.apihost || Flags.property.apibuildno) {
			Flags.property.all = true
		}

		if Flags.property.all || Flags.property.cert {
			fmt.Fprintf(color.Output, "%s\t\t%s\n", wski18n.T("client cert"), boldString(Properties.Cert))
		}

		if Flags.property.all || Flags.property.key {
			fmt.Fprintf(color.Output, "%s\t\t%s\n", wski18n.T("Client key"), boldString(Properties.Key))
		}

		if Flags.property.all || Flags.property.cacert {
			fmt.Fprintf(color.Output, "%s\t\t%s\n", wski18n.T("CA certificate"), boldString(Properties.CaCert))
		}

		if Flags.property.all || Flags.property.auth {
			fmt.Fprintf(color.Output, "%s\t\t%s\n", wski18n.T("whisk auth"), boldString(Properties.Auth))
		}

		if Flags.property.all || Flags.property.apihost {
			fmt.Fprintf(color.Output, "%s\t\t%s\n", wski18n.T("whisk API host"), boldString(Properties.APIHost))
		}

		if Flags.property.all || Flags.property.apiversion {
			fmt.Fprintf(color.Output, "%s\t%s\n", wski18n.T("whisk API version"), boldString(Properties.APIVersion))
		}

		if Flags.property.all || Flags.property.namespace {
			fmt.Fprintf(color.Output, "%s\t\t%s\n", wski18n.T("whisk namespace"), boldString(Properties.Namespace))
		}

		if Flags.property.all || Flags.property.cliversion {
			fmt.Fprintf(color.Output, "%s\t%s\n", wski18n.T("whisk CLI version"), boldString(Properties.CLIVersion))
		}

		if Flags.property.all || Flags.property.apibuild || Flags.property.apibuildno {
			info, _, err := Client.Info.Get()
			if err != nil {
				whisk.Debug(whisk.DbgError, "Client.Info.Get() failed: %s\n", err)
				info = &whisk.Info{}
				info.Build = wski18n.T("Unknown")
				info.BuildNo = wski18n.T("Unknown")
			}
			if Flags.property.all || Flags.property.apibuild {
				fmt.Fprintf(color.Output, "%s\t\t%s\n", wski18n.T("whisk API build"), boldString(info.Build))
			}
			if Flags.property.all || Flags.property.apibuildno {
				fmt.Fprintf(color.Output, "%s\t%s\n", wski18n.T("whisk API build number"), boldString(info.BuildNo))
			}
			if err != nil {
				errStr := fmt.Sprintf(
					wski18n.T("Unable to obtain API build information: {{.err}}",
						map[string]interface{}{"err": err}))
				werr := whisk.MakeWskErrorFromWskError(errors.New(errStr), err, whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
				return werr
			}
		}

		return nil
	},
}

func init() {
	propertyCmd.AddCommand(
		propertySetCmd,
		propertyUnsetCmd,
		propertyGetCmd,
	)

	// need to set property flags as booleans instead of strings... perhaps with boolApihost...
	propertyGetCmd.Flags().BoolVar(&Flags.property.cert, "cert", false, wski18n.T("client cert"))
	propertyGetCmd.Flags().BoolVar(&Flags.property.key, "key", false, wski18n.T("client key"))
	propertyGetCmd.Flags().BoolVar(&Flags.property.cacert, "cacert", false, wski18n.T("CA cert"))
	propertyGetCmd.Flags().BoolVar(&Flags.property.auth, "auth", false, wski18n.T("authorization key"))
	propertyGetCmd.Flags().BoolVar(&Flags.property.apihost, "apihost", false, wski18n.T("whisk API host"))
	propertyGetCmd.Flags().BoolVar(&Flags.property.apiversion, "apiversion", false, wski18n.T("whisk API version"))
	propertyGetCmd.Flags().BoolVar(&Flags.property.apibuild, "apibuild", false, wski18n.T("whisk API build version"))
	propertyGetCmd.Flags().BoolVar(&Flags.property.apibuildno, "apibuildno", false, wski18n.T("whisk API build number"))
	propertyGetCmd.Flags().BoolVar(&Flags.property.cliversion, "cliversion", false, wski18n.T("whisk CLI version"))
	propertyGetCmd.Flags().BoolVar(&Flags.property.namespace, "namespace", false, wski18n.T("whisk namespace"))
	propertyGetCmd.Flags().BoolVar(&Flags.property.all, "all", false, wski18n.T("all properties"))

	propertySetCmd.Flags().StringVarP(&Flags.Global.Auth, "auth", "u", "", wski18n.T("authorization `KEY`"))
	propertySetCmd.Flags().StringVar(&Flags.Global.Cert, "cert", "", wski18n.T("client cert"))
	propertySetCmd.Flags().StringVar(&Flags.Global.Key, "key", "", wski18n.T("client key"))
	propertySetCmd.Flags().StringVar(&Flags.Global.CaCert, "cacert", "", wski18n.T("CA cert"))
	propertySetCmd.Flags().StringVar(&Flags.property.apihostSet, "apihost", "", wski18n.T("whisk API `HOST`"))
	propertySetCmd.Flags().StringVar(&Flags.property.apiversionSet, "apiversion", "", wski18n.T("whisk API `VERSION`"))
	propertySetCmd.Flags().StringVar(&Flags.property.namespaceSet, "namespace", "", wski18n.T("whisk `NAMESPACE`"))

	propertyUnsetCmd.Flags().BoolVar(&Flags.property.cert, "cert", false, wski18n.T("client cert"))
	propertyUnsetCmd.Flags().BoolVar(&Flags.property.key, "key", false, wski18n.T("client key"))
	propertyUnsetCmd.Flags().BoolVar(&Flags.property.cacert, "cacert", false, wski18n.T("CA cert"))
	propertyUnsetCmd.Flags().BoolVar(&Flags.property.auth, "auth", false, wski18n.T("authorization key"))
	propertyUnsetCmd.Flags().BoolVar(&Flags.property.apihost, "apihost", false, wski18n.T("whisk API host"))
	propertyUnsetCmd.Flags().BoolVar(&Flags.property.apiversion, "apiversion", false, wski18n.T("whisk API version"))
	propertyUnsetCmd.Flags().BoolVar(&Flags.property.namespace, "namespace", false, wski18n.T("whisk namespace"))

}

func SetDefaultProperties() {
	Properties.Key = DefaultCert
	Properties.Cert = DefaultKey
	Properties.Auth = DefaultAuth
	Properties.CaCert = DefaultCaCert
	Properties.Namespace = DefaultNamespace
	Properties.APIHost = DefaultAPIHost
	Properties.APIBuild = DefaultAPIBuild
	Properties.APIBuildNo = DefaultAPIBuildNo
	Properties.APIVersion = DefaultAPIVersion
	Properties.PropsFile = DefaultPropsFile
	// Properties.CLIVersion value is set from main's init()
}

func GetPropertiesFilePath() (propsFilePath string, werr error) {
	var envExists bool

	// WSK_CONFIG_FILE environment variable overrides the default properties file path
	// NOTE: If this variable is set to an empty string or non-existent/unreadable file
	// - any existing $HOME/.wskprops is ignored
	// - a default configuration is used
	if propsFilePath, envExists = os.LookupEnv("WSK_CONFIG_FILE"); envExists {
		whisk.Debug(whisk.DbgInfo, "Using properties file '%s' from WSK_CONFIG_FILE environment variable\n", propsFilePath)
		return propsFilePath, nil
	} else {
		var err error

		propsFilePath, err = homedir.Expand(Properties.PropsFile)

		if err != nil {
			whisk.Debug(whisk.DbgError, "homedir.Expand(%s) failed: %s\n", Properties.PropsFile, err)
			errStr := fmt.Sprintf(
				wski18n.T("Unable to locate properties file '{{.filename}}': {{.err}}",
					map[string]interface{}{"filename": Properties.PropsFile, "err": err}))
			werr = whisk.MakeWskError(errors.New(errStr), whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
			return propsFilePath, werr
		}

		whisk.Debug(whisk.DbgInfo, "Using properties file home dir '%s'\n", propsFilePath)
	}

	return propsFilePath, nil
}

func loadProperties() error {
	var err error

	SetDefaultProperties()

	Properties.PropsFile, err = GetPropertiesFilePath()
	if err != nil {
		return nil
		//whisk.Debug(whisk.DbgError, "GetPropertiesFilePath() failed: %s\n", err)
		//errStr := fmt.Sprintf("Unable to load the properties file: %s", err)
		//werr := whisk.MakeWskError(errors.New(errStr), whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
		//return werr
	}

	props, err := ReadProps(Properties.PropsFile)
	if err != nil {
		whisk.Debug(whisk.DbgError, "readProps(%s) failed: %s\n", Properties.PropsFile, err)
		errStr := wski18n.T("Unable to read the properties file '{{.filename}}': {{.err}}",
			map[string]interface{}{"filename": Properties.PropsFile, "err": err})
		werr := whisk.MakeWskError(errors.New(errStr), whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
		return werr
	}

	if cert, hasProp := props["CERT"]; hasProp {
		Properties.Cert = cert
	}

	if key, hasProp := props["KEY"]; hasProp {
		Properties.Key = key
	}

	if cacert, hasProp := props["CACERT"]; hasProp {
		Properties.CaCert = cacert
	}

	if authToken, hasProp := props["AUTH"]; hasProp {
		Properties.Auth = authToken
	}

	if authToken := os.Getenv("WHISK_AUTH"); len(authToken) > 0 {
		Properties.Auth = authToken
	}

	if apiVersion, hasProp := props["APIVERSION"]; hasProp {
		Properties.APIVersion = apiVersion
	}

	if apiVersion := os.Getenv("WHISK_APIVERSION"); len(apiVersion) > 0 {
		Properties.APIVersion = apiVersion
	}

	if apiHost, hasProp := props["APIHOST"]; hasProp {
		Properties.APIHost = apiHost
	}

	if apiHost := os.Getenv("WHISK_APIHOST"); len(apiHost) > 0 {
		Properties.APIHost = apiHost
	}

	if namespace, hasProp := props["NAMESPACE"]; hasProp && len(namespace) > 0 {
		Properties.Namespace = namespace
	}

	if namespace := os.Getenv("WHISK_NAMESPACE"); len(namespace) > 0 {
		Properties.Namespace = namespace
	}

	return nil
}

func parseConfigFlags(cmd *cobra.Command, args []string) error {

	if cert := Flags.Global.Cert; len(cert) > 0 {
		Properties.Cert = cert
		if Client != nil {
			Client.Config.Cert = cert
		}
	}

	if key := Flags.Global.Key; len(key) > 0 {
		Properties.Key = key
		if Client != nil {
			Client.Config.Key = key
		}
	}

	if cacert := Flags.Global.CaCert; len(cacert) > 0 {
		Properties.Key = cacert
		if Client != nil {
			Client.Config.CaCert = cacert
		}
	}

	if auth := Flags.Global.Auth; len(auth) > 0 {
		Properties.Auth = auth
		if Client != nil {
			Client.Config.AuthToken = auth
		}
	}

	if namespace := Flags.property.namespaceSet; len(namespace) > 0 {
		Properties.Namespace = namespace
		if Client != nil {
			Client.Config.Namespace = namespace
		}
	}

	if apiVersion := Flags.Global.Apiversion; len(apiVersion) > 0 {
		Properties.APIVersion = apiVersion
		if Client != nil {
			Client.Config.Version = apiVersion
		}
	}

	if apiHost := Flags.Global.Apihost; len(apiHost) > 0 {
		Properties.APIHost = apiHost
		if Client != nil {
			Client.Config.Host = apiHost
			baseURL, err := whisk.GetURLBase(apiHost, DefaultOpenWhiskApiPath)

			if err != nil {
				whisk.Debug(whisk.DbgError, "whisk.GetURLBase(%s, %s) failed: %s\n", apiHost, DefaultOpenWhiskApiPath, err)
				errStr := wski18n.T("Invalid host address '{{.host}}': {{.err}}",
					map[string]interface{}{"host": Properties.APIHost, "err": err})
				werr := whisk.MakeWskError(errors.New(errStr), whisk.EXIT_CODE_ERR_GENERAL, whisk.DISPLAY_MSG, whisk.NO_DISPLAY_USAGE)
				return werr
			}
			Client.Config.BaseURL = baseURL
		}
	}

	if Flags.Global.Debug {
		whisk.SetDebug(true)
	}
	if Flags.Global.Verbose {
		whisk.SetVerbose(true)
	}

	return nil
}
