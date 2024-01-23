package main

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v2"

	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/xlzd/gotp"
)

// https://openvpn.net/community-resources/using-alternative-authentication-methods/
// From: https://developers.google.com/admin-sdk/directory/v1/quickstart/go
// https://build.openvpn.net/doxygen/defer_2simple_8c_source.html
// https://developers.google.com/admin-sdk/directory/v1/guides/manage-users
// https://developers.google.com/admin-sdk/directory/v1/quickstart/python
// https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go
// https://github.com/awsdocs/aws-doc-sdk-examples/blob/master/go/example_code/dynamodb/DynamoDBReadItem.go

type conf struct {
	AwsAccessKey      string `yaml:"aws_access_key"`
	AwsSecretKey      string `yaml:"aws_secret_key"`
	AwsRegion         string `yaml:"aws_region"`
	PasswordTableName string `yaml:"dynamodb_password_table"`
	Credentials       string `yaml:"gsuite_credentials,omitempty"`
	Token             string `yaml:"gsuite_token,omitempty"`
	OrgUnit           string `yaml:"gsuite_org_unit,omitempty"`
	MacTableName      string `yaml:"dynamodb_mac_table,omitempty"`
	TOTPSecret        string `yaml:"totp_secret,omitempty"`
	TOTPTableName     string `yaml:"dynamodb_totp_table,omitempty"`
}

// Item is returned entry from dynamodb for userEmail
type Item struct {
	UserID   string
	Password string
}

type MACS struct {
	UserID string
	MACS   []string
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func aesCbcPbkdf2DecryptFromBase64(password, ciphertextBase64 string) (string, error) {
	passwordBytes := []byte(password)
	data := strings.Split(ciphertextBase64, ":")
	salt, err := base64Decoding(data[0])
	if err != nil {
		return "", err
	}
	iv, err := base64Decoding(data[1])
	if err != nil {
		return "", err
	}
	ciphertext, err := base64Decoding(data[2])
	if err != nil {
		return "", err
	}

	PBKDF2_ITERATIONS := 15000
	decryptionKey := pbkdf2.Key(passwordBytes, salt, PBKDF2_ITERATIONS, 32, sha256.New)
	block, err := aes.NewCipher(decryptionKey)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decryptedtext := make([]byte, len(ciphertext))
	mode.CryptBlocks(decryptedtext, ciphertext)

	decryptedtextP, err := unpad(decryptedtext)
	if err != nil {
		return "", err
	}

	return string(decryptedtextP), nil
}

func base64Decoding(input string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func unpad(data []byte) ([]byte, error) {
	length := len(data)
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, fmt.Errorf("Invalid padding")
	}
	return data[:(length - unpadding)], nil
}

func (c *conf) getConf(conffile string) *conf {
	yamlFile, err := os.ReadFile(conffile)
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

func authorizeUser(srv *admin.Service, userEmail string, c conf) {
	usernameQuery := fmt.Sprintf("email:%s\n", userEmail)
	r, err := srv.Users.List().Customer("my_customer").Query(usernameQuery).Do()
	if err != nil {
		log.Fatalf("Unable to retrieve users in domain: %v", err)
	}

	// if 1) user exists, 2) user not suspended, 3) user a member of a specific org unit, if defined
	if len(r.Users) == 0 {
		log.Fatalf("No users found.\n")
		os.Exit(1)
	} else {
		for _, u := range r.Users {
			//https://godoc.org/google.golang.org/api/admin/directory/v1#User
			if len(c.OrgUnit) != 0 {
				OrganizationUnit := fmt.Sprintf("/%s", c.OrgUnit)
				if OrganizationUnit != u.OrgUnitPath {
					log.Fatalf("User %s found, but not part of Organizion Unit %s!", u.PrimaryEmail, OrganizationUnit)
					os.Exit(1)
				}
			}
			if u.Suspended == true {
				log.Fatalf("User %s found, but account is suspended!", u.PrimaryEmail)
				os.Exit(1)
			}
			log.Printf("%s (%s) Authorized\n", u.PrimaryEmail, u.Name.FullName)
		}
	}
}

func authenticateUser(userEmail string, userPass string, c conf) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	// Create DynamoDB client
	svc := dynamodb.New(sess)

	result, err := svc.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(c.PasswordTableName),
		Key: map[string]*dynamodb.AttributeValue{
			"UserId": {
				S: aws.String(userEmail),
			},
		},
	})
	if err != nil {
		log.Panicf(err.Error())
		os.Exit(1)
	}

	item := Item{}

	err = dynamodbattribute.UnmarshalMap(result.Item, &item)
	if err != nil {
		panic(fmt.Sprintf("Failed to unmarshal Record, %v", err))
	}

	if item.Password == "" {
		log.Println("Could not find password for: " + userEmail)
		os.Exit(1)
	}

	hash := item.Password

	match := CheckPasswordHash(userPass, hash)
	if match == false {
		log.Printf("%s NOT Authenticated\n", userEmail)
		os.Exit(1)
	}
	log.Printf("%s Authenticated\n", userEmail)
}

func verifyTOTP(userEmail string, totpCode string, c conf) {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	// Create DynamoDB client
	svc := dynamodb.New(sess)

	result, err := svc.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(c.TOTPTableName),
		Key: map[string]*dynamodb.AttributeValue{
			"UserId": {
				S: aws.String(userEmail),
			},
		},
	})
	if err != nil {
		log.Panicf(err.Error())
		os.Exit(1)
	}

	item := Item{}

	err = dynamodbattribute.UnmarshalMap(result.Item, &item)
	if err != nil {
		panic(fmt.Sprintf("Failed to unmarshal Record, %v", err))
	}

	if item.Password == "" {
		log.Println("Could not find password for: " + userEmail)
		os.Exit(1)
	}
	decryptedSecret, err := aesCbcPbkdf2DecryptFromBase64(c.TOTPSecret, item.Password)
	if err != nil {
		log.Println("Could not decrypt TOTP Secret: " + err.Error())
		os.Exit(1)
	}
	totp := gotp.NewDefaultTOTP(decryptedSecret)
	TOTPGenResult := totp.Now()
	// fmt.Println("TOTP Code Generated: " + TOTPGenResult)
	// fmt.Println("TOTP Code Provided: " + totpCode)
	if TOTPGenResult != totpCode {
		log.Printf("ERROR: One time codes don't match! %s NOT Authenticated\n", userEmail)
		os.Exit(1)
	}
	log.Printf("%s TOTP verified!\n", userEmail)
}

func verifyMac(userEmail string, c conf) {
	// first make sure we're getting a MAC address
	var MACaddress string
	if len(os.Getenv("IV_HWADDR")) == 0 {
		log.Println("No MAC address provided!")
		os.Exit(1)
	} else {
		MACaddress = fmt.Sprintf("%s", os.Getenv("IV_HWADDR"))
	}
	// fmt.Println("MAC address provided: " + MACaddress)
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	// Create DynamoDB client
	svc := dynamodb.New(sess)

	result, err := svc.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String(c.MacTableName),
		Key: map[string]*dynamodb.AttributeValue{
			"UserId": {
				S: aws.String(userEmail),
			},
		},
	})
	if err != nil {
		log.Panicf(err.Error())
		os.Exit(1)
	}

	item := MACS{}

	err = dynamodbattribute.UnmarshalMap(result.Item, &item)
	if err != nil {
		panic(fmt.Sprintf("Failed to unmarshal Record, %v", err))
	}

	if item.UserID == "" {
		log.Printf("Could not find MACs for: %s, populating with: %s", userEmail, MACaddress)
		_, err := svc.PutItem(&dynamodb.PutItemInput{
			TableName: aws.String(c.MacTableName),
			Item: map[string]*dynamodb.AttributeValue{
				"UserId": {
					S: aws.String(userEmail),
				},
				"MACS": {
					SS: []*string{
						aws.String(MACaddress),
					},
				},
			},
		})
		if err != nil {
			log.Panicf(err.Error())
			os.Exit(1)
		}
	} else {
		if slices.Contains(item.MACS, MACaddress) == false {
			log.Printf("ERROR: MAC address %s not found for user %s!\n", MACaddress, userEmail)
			os.Exit(1)
		} else {
			log.Printf("%s MAC address verified as %s!\n", userEmail, MACaddress)
		}
	}
}

func main() {
	var c conf
	// TODO: make this look locally for config file as well for testing
	// gsuiteConfig := "/etc/openvpn/gsuite_auth_config.yaml"
	gsuiteConfig := "./gsuite_auth_config.yaml"
	c.getConf(gsuiteConfig)
	os.Setenv("AWS_ACCESS_KEY_ID", c.AwsAccessKey)
	os.Setenv("AWS_SECRET_ACCESS_KEY", c.AwsSecretKey)
	os.Setenv("AWS_REGION", c.AwsRegion)

	userEmail := fmt.Sprintf("%s", os.Getenv("username"))
	var userPass string
	var totpCode string
	if c.TOTPTableName != "" {
		// if we've enabled TOTP in the client config, we need to decode the password string
		// Example: password=SCRV1:YmFm:MTgzNw==
		passString := fmt.Sprintf("%s", os.Getenv("password"))
		passParts := strings.Split(passString, ":")
		userPassEnc := fmt.Sprintf("%s", passParts[1])
		userPassDs, _ := b64.StdEncoding.DecodeString(userPassEnc)
		userPass = fmt.Sprintf("%s", userPassDs)
		totpCodeEnc := fmt.Sprintf("%s", passParts[2])
		totpCodeDs, _ := b64.StdEncoding.DecodeString(totpCodeEnc)
		totpCode = fmt.Sprintf("%s", totpCodeDs)
	} else {
		// Otherwise, password is just the password string
		userPass = fmt.Sprintf("%s", os.Getenv("password"))
	}

	// assuming you'll always want to authenticate against the password table
	authenticateUser(userEmail, userPass, c)

	// if we've configured credentials in the config, authenticate against gsuite
	if c.Credentials != "" {
		// log.Println("GSuite membership check enabled")
		b, err := os.ReadFile(c.Credentials)
		if err != nil {
			log.Fatalf("Unable to read client secret file: %v", err)
		}

		// If modifying these scopes, delete your previously saved token.json.
		config, err := google.ConfigFromJSON(b, admin.AdminDirectoryUserReadonlyScope)
		if err != nil {
			log.Fatalf("Unable to parse client secret file to config: %v", err)
		}
		client := getClient(config, c.Token)

		// TODO: fix deprecation warning
		srv, err := admin.New(client)
		if srv == nil {
			// this is actually just here to make the linter happy
			log.Fatalf("Unable to retrieve directory Client %v", err)
			os.Exit(1)
		}
		if err != nil {
			log.Fatalf("Unable to retrieve directory Client %v", err)
			os.Exit(1)
		}
		authorizeUser(srv, userEmail, c)
	}

	if c.TOTPTableName != "" {
		// log.Println("TOTP check enabled")
		verifyTOTP(userEmail, totpCode, c)
	}
	if c.MacTableName != "" {
		// log.Println("MAC address check enabled")
		verifyMac(userEmail, c)
	}
	os.Exit(0)
}
