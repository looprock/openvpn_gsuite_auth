package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	//"github.com/spf13/viper"

	"gopkg.in/yaml.v2"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
)

// https://openvpn.net/community-resources/using-alternative-authentication-methods/
// From: https://developers.google.com/admin-sdk/directory/v1/quickstart/go
// https://build.openvpn.net/doxygen/defer_2simple_8c_source.html
// https://developers.google.com/admin-sdk/directory/v1/guides/manage-users
// https://developers.google.com/admin-sdk/directory/v1/quickstart/python
// https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go
// https://github.com/awsdocs/aws-doc-sdk-examples/blob/master/go/example_code/dynamodb/DynamoDBReadItem.go

type conf struct {
	GsuiteDomain string `yaml:"domain"`
	Credentials  string `yaml:"credentials"`
	Token        string `yaml:"token"`
	TableName    string `yaml:"dynamodb_table"`
	OrgUnit      string `yaml:"orgunit,omitempty"`
}

// Item is returned entry from dynamodb for userEmail
type Item struct {
	UserID   string
	Password string
	UserUUID string
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func (c *conf) getConf(conffile string) *conf {
	yamlFile, err := ioutil.ReadFile(conffile)
	check(err)
	err = yaml.Unmarshal(yamlFile, c)
	check(err)
	return c
}

// Retrieve a token, saves the token, then returns the generated client.
func getClient(config *oauth2.Config, tokFile string) *http.Client {
	// The file token.json stores the user's access and refresh tokens, and is
	// created automatically when the authorization flow completes for the first
	// time.
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokFile, tok)
	}
	return config.Client(context.Background(), tok)
}

// Request a token from the web, then returns the retrieved token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code: %v", err)
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	return tok
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

// CheckPasswordHash returns boolean result of comparison of a hash and password
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func main() {
	var c conf
	gsuiteConfig := "/etc/openvpn/gsuite_auth_config.yaml"
	c.getConf(gsuiteConfig)
	OrganizationUnit := fmt.Sprintf("/%s", c.OrgUnit)
	fmt.Printf("AWS_DEFAULT_REGION: %s", os.Getenv("AWS_DEFAULT_REGION"))

	b, err := ioutil.ReadFile(c.Credentials)
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	// If modifying these scopes, delete your previously saved token.json.
	config, err := google.ConfigFromJSON(b, admin.AdminDirectoryUserReadonlyScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	client := getClient(config, c.Token)

	srv, err := admin.New(client)
	if err != nil {
		log.Fatalf("Unable to retrieve directory Client %v", err)
	}

	userEmail := fmt.Sprintf("%s@%s", os.Getenv("username"), c.GsuiteDomain)
	usernameQuery := fmt.Sprintf("email:%s\n", userEmail)
	r, err := srv.Users.List().Customer("my_customer").Query(usernameQuery).Do()
	if err != nil {
		log.Fatalf("Unable to retrieve users in domain: %v", err)
	}

	// if 1) user exists, 2) user not suspended, 3) user a member of a specific org unit, if defined
	if len(r.Users) == 0 {
		fmt.Print("No users found.\n")
		os.Exit(1)
	} else {
		for _, u := range r.Users {
			//https://godoc.org/google.golang.org/api/admin/directory/v1#User
			if len(OrganizationUnit) != 0 {
				if OrganizationUnit != u.OrgUnitPath {
					fmt.Printf("User %s found, but not part of Organizion Unit %s!", u.PrimaryEmail, OrganizationUnit)
					os.Exit(1)
				}
			}
			if u.Suspended == true {
				fmt.Printf("User %s found, but account is suspended!", u.PrimaryEmail)
				os.Exit(1)
			}
			fmt.Printf("%s (%s) Authorized\n", u.PrimaryEmail, u.Name.FullName)
		}
	}
	// yay, authorization worked, now lets do authentication by validating a password stored in a database

	password := os.Getenv("password")

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	// Create DynamoDB client
	svc := dynamodb.New(sess)

	result, err := svc.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(c.TableName),
		Key: map[string]*dynamodb.AttributeValue{
			"UserId": {
				S: aws.String(userEmail),
			},
		},
	})
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	item := Item{}

	err = dynamodbattribute.UnmarshalMap(result.Item, &item)
	if err != nil {
		panic(fmt.Sprintf("Failed to unmarshal Record, %v", err))
	}

	if item.Password == "" {
		fmt.Println("Could not find password for: " + userEmail)
		os.Exit(1)
	}

	hash := item.Password

	match := CheckPasswordHash(password, hash)
	if match == false {
		fmt.Printf("%s NOT Authenticated\n", userEmail)
		os.Exit(1)
	}
	fmt.Printf("%s Authenticated\n", userEmail)
	os.Exit(1)
}
