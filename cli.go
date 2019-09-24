package jwtauth

import (
	"errors"
	"fmt"
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

const defaultAddress = "localhost"
const defaultMount = "oidc"
const defaultPort = "8250"

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

	port, ok := m["port"]
	if !ok {
		port = defaultPort
	}

	// looking for an IP address here
	reAddress := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	address := defaultAddress
	if reAddress.MatchString(c.Address()) {
		address = reAddress.FindString(c.Address())
	}

	role := m["role"]

	authURL, err := fetchAuthURL(c, role, mount, address, port)
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
			response = successHTML
		}
		err = entityCheck(c, secret)
		if err != nil {
			summary, detail := parseError(err)
			response = errorHTML(summary, detail)
		}
		w.Write([]byte(response))
		doneCh <- loginResp{secret, err}
	})

	listener, err := net.Listen("tcp", ":"+port)
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

func fetchAuthURL(c *api.Client, role, mount, address, port string) (string, error) {
	var authURL string

	data := map[string]interface{}{
		"role":         role,
		"redirect_uri": fmt.Sprintf("http://%s:%s/oidc/callback", address, port),
	}

	secret, err := c.Logical().Write(fmt.Sprintf("auth/%s/oidc/auth_url", mount), data)
	if err != nil {
		return "", err
	}

	if secret != nil {
		authURL = secret.Data["auth_url"].(string)
	}

	if authURL == "" {
		return "", fmt.Errorf("unable to authorize role %q - check vault logs for more information", role)
	}

	return authURL, nil
}

// openURL opens the specified URL in the default browser of the user.
// Source: https://stackoverflow.com/a/39324149/453290
func openURL(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
		url = strings.Replace(url, "&", "^&", -1)
	case "darwin":
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

  port=<string>
      Optional localhost port to use for OIDC callback (default: 8250).
`

	return strings.TrimSpace(help)
}

// entityCheck checks if an entity with username@wish.com exists or not. If it doesn't exist, it creates it approrpiately
// If it exists, then it links it appropriately
// End result: The log in request will be linked to the right entity
func entityCheck(c *api.Client, secret *api.Secret) error {

	createdEntityObj, err := c.Logical().Read(fmt.Sprintf("identity/entity/id/%s", secret.Auth.EntityID))
	if err != nil {
		return err
	}
	entityData := createdEntityObj.Data["aliases"].([]interface{})
	// Since we just logged in, there is guaranteed to be atleast 1 alias
	aliasData := entityData[0].(map[string]interface{})
	// Check to see what the entity name currently is
	actualEntityName := createdEntityObj.Data["name"].(string)
	// Check to see what the entity name SHOULD be. if it doesn't contain @wish.com, then add it as some aliases don't contain it (such as userpass)
	entityNameShouldBe := aliasData["name"].(string)
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
	if existingEntityObj != nil && err == nil {
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
