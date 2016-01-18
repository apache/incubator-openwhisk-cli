package commands

import (
	"fmt"
	"net/http"
	"os"

	"github.com/mitchellh/go-homedir"
	"github.ibm.com/Bluemix/whisk-cli/client"
)

var whisk *client.Client

// PropsFile is the path to the current props file (default ~/.wskprops).
var PropsFile string

func init() {
	var err error
	PropsFile, err = homedir.Expand(defaultPropsFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	whisk, err = initializeClient()

}

func initializeClient() (*client.Client, error) {
	clientConfig := &client.Config{}

	// read props

	props, err := readProps(PropsFile)
	if err != nil {
		return nil, err
	}

	if namespace, hasProp := props["NAMESPACE"]; hasProp {
		clientConfig.Namespace = namespace
	}

	if authToken, hasProp := props["AUTH"]; hasProp {
		clientConfig.AuthToken = authToken
	}

	// TODO :: set clientConfig based on environment variables
	// Environment variables override prop file variables

	// Setup client
	whisk, err = client.New(http.DefaultClient, clientConfig)
	if err != nil {
		return nil, err
	}

	return whisk, nil
}

func Execute() error {
	WskCmd.AddCommand(
		authCmd,
		listCmd,
		whoamiCmd,
		triggerCmd,
		actionCmd,
		sdkCmd,
		ruleCmd,
		activationCmd,
		packageCmd,
		healthCmd,
		cleanCmd,
		namespaceCmd,
		versionCmd,

		// hidden
		configCmd,
		propsCmd,
	)

	return WskCmd.Execute()
}
