package strato

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/antchfx/htmlquery"
	"k8s.io/klog/v2"
)

type DNSConfig struct {
	DMARCType string
	SPFType   string
	Records   []DNSRecord
}

type DNSRecord struct {
	Type   string
	Prefix string
	Value  string
}

type StratoClient struct {
	api        string
	identifier string
	password   string
	order      string
	domain     string
	cID        string
	session    *http.Client
	sessionID  string
}

// NewStratoClient initializes and returns a new StratoClient instance
func NewStratoClient(api, identifier, password, order, domain string) (*StratoClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	client := &StratoClient{
		api:        api,
		identifier: identifier,
		password:   password,
		order:      order,
		domain:     domain,
		session: &http.Client{
			Jar: jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Prevent following redirects
				return http.ErrUseLastResponse
			},
		},
	}

	// Authenticate during initialization
	if err := client.authenticate(); err != nil {
		return nil, err
	}

	// Find cID
	if err := client.populatePackageID(); err != nil {
		return nil, err
	}
	return client, nil
}

// authenticate sends credentials to a webform and stores session cookies
func (c *StratoClient) authenticate() error {
	// We need to establish a session first.
	// This is done by sending a GET request to the login page.
	// The server will respond with a Set-Cookie header containing the session ID.
	// We need to store this cookie in the cookie jar for subsequent requests.
	req, err := http.NewRequest("GET", c.api, nil)
	if err != nil {
		return err
	}
	// Send the request
	resp, err := c.session.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	cookies := resp.Header.Values("Set-Cookie")
	for _, cookie := range cookies {
		if strings.Contains(cookie, "ksb_session") {
			klog.V(6).Infof("ksb id Cookie: %s", cookie)
			break
		}
	}

	// Now we can send the login form data to the server.
	form := []string{}
	form = append(form, "identifier="+c.identifier)
	form = append(form, "passwd="+c.password)
	form = append(form, "action_customer_login.x=Login")
	queryString := strings.Join(form, "&")

	req, err = http.NewRequest("POST", c.api, bytes.NewBufferString(queryString))
	if err != nil {
		return err
	}
	// Set the Content-Type header to application/x-www-form-urlencoded
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	resp, err = c.session.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound { // 302
		// Strato uses a 302 redirect for successful login
		// The user is redirected to the dashboard page
		location := resp.Header.Get("Location")
		parsedURL, err := url.Parse(location)
		if err != nil {
			return err
		}
		c.sessionID = parsedURL.Query().Get("sessionID")
		if c.sessionID == "" {
			return errors.New("sessionID not found in redirect URL")
		}
		klog.V(6).Infof("Session ID: %s", c.sessionID)
		return nil
	} else if resp.StatusCode == http.StatusOK { // 200
		// If the status code is 200, it means the login failed
		// and the user is presented with the same login page again
		return errors.New("authentication failed")
	}
	return errors.New("unexpected response status: " + resp.Status)
}

func (c *StratoClient) populatePackageID() error {
	getURL := c.api +
		"?sessionID=" + c.sessionID +
		"&cID=0" +
		"&node=kds_CustomerEntryPage"

	// Create a new HTTP request
	req, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		return nil
	}
	// Send the request
	resp, err := c.session.Do(req)
	if err != nil {
		return nil
	}
	doc, err := htmlquery.Parse(resp.Body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	div := htmlquery.FindOne(doc, "//div[@data-pkg-name-order='"+c.order+"']")
	if div == nil {
		return errors.New("failed to find order")
	}
	linkNode := htmlquery.FindOne(div, ".//a")
	if linkNode == nil {
		return errors.New("failed to find link")
	}
	link := htmlquery.SelectAttr(linkNode, "href")
	if link == "" {
		return errors.New("failed to find link value")
	}
	// Extract the cID from the link
	parts := strings.Split(link, "&")
	for _, part := range parts {
		if strings.HasPrefix(part, "cID=") {
			cID := strings.TrimPrefix(part, "cID=")
			c.cID = cID
			break
		}
	}
	if c.cID == "" {
		return errors.New("failed to find cID in link")
	}
	return nil
}

// getDNSRecords retrieves DNS records from the website
func (c *StratoClient) GetDNSConfiguration() (DNSConfig, error) {
	getURL := c.api +
		"?sessionID=" + c.sessionID +
		"&cID=" + c.cID +
		"&node=ManageDomains" +
		"&action_show_txt_records" +
		"&vhost=" + c.domain

	// Create a new HTTP request
	req, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		return DNSConfig{}, err
	}
	// Send the request
	resp, err := c.session.Do(req)
	if err != nil {
		return DNSConfig{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return DNSConfig{}, errors.New("failed to fetch TXT records")
	}

	doc, err := htmlquery.Parse(resp.Body)
	if err != nil {
		return DNSConfig{}, err
	}
	defer resp.Body.Close()

	config := DNSConfig{}

	form := htmlquery.FindOne(doc, "//form[@id='jss_txt_record_form']")
	if form == nil {
		return DNSConfig{}, errors.New("failed to find form element")
	}

	dmarcNode := htmlquery.FindOne(form, "//input[@name='dmarc_type' and @checked]")
	if dmarcNode == nil {
		return DNSConfig{}, errors.New("failed to find dmarc_type element")
	}
	dmarcType := htmlquery.SelectAttr(dmarcNode, "value")
	if dmarcType == "" {
		return DNSConfig{}, errors.New("failed to find dmarc_type value")
	}
	config.DMARCType = dmarcType

	spfNode := htmlquery.FindOne(form, "//input[@name='spf_type' and @checked]")
	if spfNode == nil {
		return DNSConfig{}, errors.New("failed to find spf_type element")
	}
	spfType := htmlquery.SelectAttr(spfNode, "value")
	if spfType == "" {
		return DNSConfig{}, errors.New("failed to find spf_type value")
	}
	config.SPFType = spfType

	var records []DNSRecord
	recordNodes := htmlquery.Find(form, "//div[@id='jss_txt_container']/div[contains(@class, 'txt-record-tmpl')]")
	for _, recordNode := range recordNodes {
		recordTypeNode := htmlquery.FindOne(recordNode, ".//select[@name='type']/option[@selected]")
		recordPrefixNode := htmlquery.FindOne(recordNode, ".//input[@name='prefix']")
		recordValueNode := htmlquery.FindOne(recordNode, ".//textarea[@name='value']")

		if recordTypeNode != nil && recordValueNode != nil {
			record := DNSRecord{
				Type:   htmlquery.SelectAttr(recordTypeNode, "value"),
				Prefix: htmlquery.SelectAttr(recordPrefixNode, "value"),
				Value:  htmlquery.InnerText(recordValueNode),
			}
			records = append(records, record)
		}
	}
	config.Records = records
	return config, nil
}

func (c *StratoClient) SetDNSConfiguration(config DNSConfig) error {
	setURL := c.api +
		"?sessionID=" + c.sessionID +
		"&cID=" + c.cID +
		"&action_change_txt_records"

	form := []string{}
	form = append(form, "sessionID="+c.sessionID)
	form = append(form, "cID=1")
	form = append(form, "node=ManageDomains")
	form = append(form, "vhost="+c.domain)
	form = append(form, "dmarc_type="+config.DMARCType)
	form = append(form, "spf_type="+config.SPFType)
	for _, record := range config.Records {
		form = append(form, "type="+record.Type)
		form = append(form, "prefix="+record.Prefix)
		form = append(form, "value="+record.Value)
	}
	form = append(form, "action_change_txt_records=Einstellung übernehmen")
	queryString := strings.Join(form, "&")

	req, err := http.NewRequest("POST", setURL, bytes.NewBufferString(queryString))
	if err != nil {
		return err
	}
	// Set the Content-Type header to application/x-www-form-urlencoded
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request
	resp, err := c.session.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound { // 302
		// 302 redirect indicates a successful update
		return nil
	} else if resp.StatusCode == http.StatusOK { // 200
		// If the status code is 200, it means the update failed
		// and the user is presented with the same page again
		return errors.New("update failed")
	}
	return errors.New("unexpected response status: " + resp.Status)
}
