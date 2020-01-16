package jwtauth

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strings"

	"github.com/hashicorp/vault/api"
)

const defaultMount = "oidc"
const defaultListenAddress = "localhost"
const defaultPort = "8250"
const defaultCallbackHost = "localhost"
const defaultCallbackMethod = "http"

var errorRegex = regexp.MustCompile(`(?s)Errors:.*\* *(.*)`)

type CLIHandler struct{}

type loginResp struct {
	secret *api.Secret
	err    error
}

func (h *CLIHandler) Auth(c *api.Client, m map[string]string) (*api.Secret, error) {
	// handle ctrl-c while waiting for the callback
	sigintCh := make(chan os.Signal, 1)
	signal.Notify(sigintCh, os.Interrupt)
	defer signal.Stop(sigintCh)

	doneCh := make(chan loginResp)

	mount, ok := m["mount"]
	if !ok {
		mount = defaultMount
	}

	listenAddress, ok := m["listenaddress"]
	if !ok {
		listenAddress = defaultListenAddress
	}

	port, ok := m["port"]
	if !ok {
		port = defaultPort
	}

	callbackHost, ok := m["callbackhost"]
	if !ok {
		callbackHost = defaultCallbackHost
	}

	callbackMethod, ok := m["callbackmethod"]
	if !ok {
		callbackMethod = defaultCallbackMethod
	}

	callbackPort, ok := m["callbackport"]
	if !ok {
		callbackPort = port
	}

	role := m["role"]

	authURL, err := fetchAuthURL(c, role, mount, callbackPort, callbackMethod, callbackHost)
	if err != nil {
		return nil, err
	}

	// Set up callback handler
	http.HandleFunc("/oidc/callback", func(w http.ResponseWriter, req *http.Request) {
		var response string

		query := req.URL.Query()
		code := query.Get("code")
		state := query.Get("state")
		data := map[string][]string{
			"code":  {code},
			"state": {state},
		}

		secret, err := c.Logical().ReadWithData(fmt.Sprintf("auth/%s/oidc/callback", mount), data)
		if err != nil {
			summary, detail := parseError(err)
			response = errorHTML(summary, detail)
		} else {
			// Only want to do entity check if vault returns a successful login
			err = entityCheck(c, secret)
			if err != nil {
				summary, detail := parseError(err)
				response = errorHTML(summary, detail)
			} else {
				response = successHTML
			}
		}

		w.Write([]byte(response))
		doneCh <- loginResp{secret, err}
	})

	listener, err := net.Listen("tcp", listenAddress+":"+port)
	if err != nil {
		return nil, err
	}
	defer listener.Close()

	// Open the default browser to the callback URL.
	fmt.Fprintf(os.Stderr, "Complete the login via your OIDC provider. Launching browser to:\n\n    %s\n\n\n", authURL)
	if err := openURL(authURL); err != nil {
		fmt.Fprintf(os.Stderr, "Error attempting to automatically open browser: '%s'.\nPlease visit the authorization URL manually.", err)
	}

	// Start local server
	go func() {
		err := http.Serve(listener, nil)
		if err != nil && err != http.ErrServerClosed {
			doneCh <- loginResp{nil, err}
		}
	}()

	// Wait for either the callback to finish or SIGINT to be received
	select {
	case s := <-doneCh:
		return s.secret, s.err
	case <-sigintCh:
		return nil, errors.New("Interrupted")
	}
}

func fetchAuthURL(c *api.Client, role, mount, callbackport string, callbackMethod string, callbackHost string) (string, error) {
	var authURL string

	data := map[string]interface{}{
		"role":         role,
		"redirect_uri": fmt.Sprintf("%s://%s:%s/oidc/callback", callbackMethod, callbackHost, callbackport),
	}

	secret, err := c.Logical().Write(fmt.Sprintf("auth/%s/oidc/auth_url", mount), data)
	if err != nil {
		return "", err
	}

	if secret != nil {
		authURL = secret.Data["auth_url"].(string)
	}

	if authURL == "" {
		return "", fmt.Errorf("Unable to authorize role %q - check vault logs for more information", role)
	}

	return authURL, nil
}

// isWSL tests if the binary is being run in Windows Subsystem for Linux
func isWSL() bool {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return false
	}
	data, err := ioutil.ReadFile("/proc/version")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read /proc/version.\n")
		return false
	}
	return strings.Contains(strings.ToLower(string(data)), "microsoft")
}

// openURL opens the specified URL in the default browser of the user.
// Source: https://stackoverflow.com/a/39324149/453290
func openURL(url string) error {
	var cmd string
	var args []string

	switch {
	case "windows" == runtime.GOOS || isWSL():
		cmd = "cmd.exe"
		args = []string{"/c", "start"}
		url = strings.Replace(url, "&", "^&", -1)
	case "darwin" == runtime.GOOS:
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}

// parseError converts error from the API into summary and detailed portions.
// This is used to present a nicer UI by splitting up *known* prefix sentences
// from the rest of the text. e.g.
//
//    "No response from provider. Gateway timeout from upstream proxy."
//
// becomes:
//
//    "No response from provider.", "Gateway timeout from upstream proxy."
func parseError(err error) (string, string) {
	headers := []string{errNoResponse, errLoginFailed, errTokenVerification}
	summary := "Login error"
	detail := ""

	errorParts := errorRegex.FindStringSubmatch(err.Error())
	switch len(errorParts) {
	case 0:
		summary = ""
	case 1:
		detail = errorParts[0]
	case 2:
		for _, h := range headers {
			if strings.HasPrefix(errorParts[1], h) {
				summary = h
				detail = strings.TrimSpace(errorParts[1][len(h):])
				break
			}
		}
		if detail == "" {
			detail = errorParts[1]
		}
	}

	return summary, detail
}

// entityCheck checks if an entity with username@wish.com exists or not. If it doesn't exist, it creates it approrpiately
// If it exists, then it links it appropriately
// End result: The log in request will be linked to the right entity
func entityCheck(c *api.Client, secret *api.Secret) error {

	createdEntityObj, err := c.Logical().Read(fmt.Sprintf("identity/entity/id/%s", secret.Auth.EntityID))
	if err != nil {
		return err
	}
	entityData, safelyConverted := createdEntityObj.Data["aliases"].([]interface{})
	if !safelyConverted || len(entityData) == 0 {
		return fmt.Errorf("Error extracting aliases from entity")
	}
	// Since we just logged in, there is guaranteed to be atleast 1 alias
	aliasData, safelyConverted := entityData[0].(map[string]interface{})
	if !safelyConverted {
		return fmt.Errorf("Error extracting an alias from entity")
	}
	// Check to see what the entity name currently is
	actualEntityName, safelyConverted := createdEntityObj.Data["name"].(string)
	if !safelyConverted || actualEntityName == "" {
		return fmt.Errorf("Error extracting entity name")
	}
	// Check to see what the entity name SHOULD be. if it doesn't contain @wish.com, then add it as some aliases don't contain it (such as userpass)
	entityNameShouldBe, safelyConverted := aliasData["name"].(string)
	if !safelyConverted || entityNameShouldBe == "" {
		return fmt.Errorf("Error extracting alias name")
	}
	if !strings.HasSuffix(entityNameShouldBe, "@wish.com") {
		entityNameShouldBe = entityNameShouldBe + "@wish.com"
	}
	fmt.Printf("\n The actual entity name: %s   The expected entity name:  %s \n", actualEntityName, entityNameShouldBe)
	// Check to see if the entity name is equal. If equal, that means we already have the correct entity and don't need to do anything
	// If not equal then we need to
	// a) either find an entity with that name if it exists (eg. person logged into userpass first) -> need to merge in this case
	// b) entity name with that name doesn't exist -> simply update our name to the name it should be

	// Equal, means this is not first login, simply return nil (no error)
	if actualEntityName == entityNameShouldBe {
		return nil
	}

	// Try to find an entity name with the supposed name...
	existingEntityObj, err := c.Logical().Read(fmt.Sprintf("identity/entity/name/%s", entityNameShouldBe))
	if err != nil {
		return err
	}
	// If it exists -> Need to merge
	if existingEntityObj != nil {
		// Entity with that name exists AND is different from this entity created
		// So we need to merge the two entities together
		// This will happen user's data is synced using userpass before OIDC
		// The entity object that has the correct name is the right one and we should merge the newly created entity INTO that
		data := map[string]interface{}{
			"to_entity_id":    existingEntityObj.Data["id"],
			"from_entity_ids": secret.Auth.EntityID,
		}
		_, err = c.Logical().Write("identity/entity/merge", data)
		if err != nil {
			return err
		}
		fmt.Printf("\n Merged two entities together: %s %s \n", existingEntityObj.Data["id"], secret.Auth.EntityID)
		return nil
	}

	// If here, it means we haven't found any entitiy with the actual name, so we should update our name to the supposed name
	data := map[string]interface{}{
		"name": entityNameShouldBe,
	}
	_, err = c.Logical().Write(fmt.Sprintf("identity/entity/id/%s", secret.Auth.EntityID), data)

	// For readibility purposes, otherwise could just do return err and would have same result as below
	if err != nil {
		return err
	}
	return nil
}

// Help method for OIDC cli
func (h *CLIHandler) Help() string {
	help := `
Usage: vault login -method=oidc [CONFIG K=V...]
  The OIDC auth method allows users to authenticate using an OIDC provider.
  The provider must be configured as part of a role by the operator.
  Authenticate using role "engineering":
      $ vault login -method=oidc role=engineering
      Complete the login via your OIDC provider. Launching browser to:
          https://accounts.google.com/o/oauth2/v2/...
  The default browser will be opened for the user to complete the login. Alternatively,
  the user may visit the provided URL directly.
Configuration:
  role=<string>
      Vault role of type "OIDC" to use for authentication.
  listenaddress=<string>
    Optional address to bind the OIDC callback listener to (default: localhost).
  port=<string>
    Optional localhost port to use for OIDC callback (default: 8250).
  callbackmethod=<string>
    Optional method to to use in OIDC redirect_uri (default: http).
  callbackhost=<string>
    Optional callback host address to use in OIDC redirect_uri (default: localhost).
  callbackport=<string>
      Optional port to to use in OIDC redirect_uri (default: the value set for port).
`

	return strings.TrimSpace(help)
}