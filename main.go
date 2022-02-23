package main

import (
	"fmt"
	"log"
	"os"

	ldap "github.com/go-ldap/ldap/v3"
	"gopkg.in/yaml.v2"
)

const (
	userFilter = "(" +
		"&(objectClass=user)" +
		// only enabled users
		"(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
		//only with email
		"(mail=*)" +
		")"
	userOUFilter    = "(objectClass=organizationalUnit)"
	mailGroupFilter = "(objectClass=group)"
)

var UserAttributes = []string{ // A list attributes to retrieve
	"dn",
}
var UserOUAttributes = []string{ // A list attributes to retrieve
	"dn",
	"name",
	"description",
}
var MailGroupAttributes = []string{ // A list attributes to retrieve
	"dn",
	"name",
}

type Config struct {
	BindUsername     string `yaml:"bindUsername"`
	BindPassword     string `yaml:"bindPassword"`
	UserBaseOU       string `yaml:"userBaseOU"`
	UserBaseDN       string `yaml:"userBaseDN"`
	GroupBaseDN      string `yaml:"groupBaseDN"`
	DomainController string `yaml:"domainController"`
}

func main() {

	var groupComparsion = map[string]string{}

	//config
	cnf, err := os.Open("config.yml")
	if err != nil {
		log.Fatal(err)
	}
	defer cnf.Close()

	var cfg Config
	decoder := yaml.NewDecoder(cnf)
	err = decoder.Decode(&cfg)
	if err != nil {
		log.Fatal(err)
	}

	userSearchRequest := ldap.NewSearchRequest(
		cfg.UserBaseDN, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		userFilter,
		UserAttributes,
		nil,
	)

	userOUSearchRequest := ldap.NewSearchRequest(
		cfg.UserBaseDN, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		userOUFilter,
		UserOUAttributes,
		nil,
	)

	mailGroupSearchRequest := ldap.NewSearchRequest(
		cfg.GroupBaseDN, // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		mailGroupFilter,
		MailGroupAttributes,
		nil,
	)

	l, err := Connect(cfg.DomainController)
	if err != nil {
		log.Fatal(err)
	}
	err = l.Bind(cfg.BindUsername, cfg.BindPassword)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	userOUSearchResult, err := l.Search(userOUSearchRequest)
	if err != nil {
		log.Fatal(err)
	}

	userSearchResult, err := l.Search(userSearchRequest)
	if err != nil {
		log.Fatal(err)
	}

	mailGroupSearchResult, err := l.Search(mailGroupSearchRequest)
	if err != nil {
		log.Fatal(err)
	}

	recreateExistingGroups(
		userOUSearchResult,
		mailGroupSearchResult,
		l,
		groupComparsion,
		cfg)

	fillGroups(userSearchResult, l, cfg, groupComparsion)

}

// Ldap Connection without TLS
func Connect(fqdn string) (*ldap.Conn, error) {
	l, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", fqdn))
	if err != nil {
		return nil, err
	}
	return l, nil
}

func recreateExistingGroups(
	userOUSearchRes, mailGroupSearchRes *ldap.SearchResult,
	l *ldap.Conn,
	groupComp map[string]string,
	cfg Config) {

	mailGroups := mailGroupSearchRes.Entries

	for _, ou := range userOUSearchRes.Entries {
		ouName := ou.GetAttributeValue("name")
		ouDesc := ou.GetAttributeValue("description")

		if ouDesc != "" {
			groupComp[ouName] = ouDesc
			ouName = ouDesc
			fmt.Println("OU name=", ouName)

			for _, group := range mailGroups {
				groupName := group.GetAttributeValue("name")
				if groupName == ouName {
					//remove group
					delGroupReq := ldap.NewDelRequest(
						group.DN,
						nil)
					fmt.Println("Del Group")
					fmt.Println(delGroupReq)
					if err := l.Del(delGroupReq); err != nil {
						log.Fatal(err)
					}
				}
			}
			addGroupReq := ldap.NewAddRequest(
				"CN="+ouName+","+cfg.GroupBaseDN,
				nil)
			addGroupReq.Attribute("objectClass", []string{"group", "top"})
			addGroupReq.Attribute("groupType", []string{"-2147483646"})
			addGroupReq.Attribute("sAMAccountName", []string{ouName})
			fmt.Println("Add Group")
			fmt.Println(addGroupReq)
			fmt.Printf("\n" + "\n")
			if err := l.Add(addGroupReq); err != nil {
				log.Fatal("Failed to Add Group: ", err)
			}
		}

	}
}

func fillGroups(
	userSearchRes *ldap.SearchResult,
	l *ldap.Conn,
	cfg Config,
	groupComp map[string]string) {

	for _, user := range userSearchRes.Entries {
		userOUnames := getOUnamesFromDN(user, cfg)
		for _, ouName := range userOUnames {
			ouName, exists := groupComp[ouName]
			if exists {
				fmt.Println("ouname= " + ouName)

				modGroupReq := ldap.NewModifyRequest(
					"CN="+ouName+","+cfg.GroupBaseDN,
					nil,
				)
				modGroupReq.Add("member", []string{user.DN})
				if err := l.Modify(modGroupReq); err != nil {
					log.Fatal("fillGroup", err)
				}
				fmt.Println("Add member")
				fmt.Println(modGroupReq)
			}
		}
	}
}

func getOUnamesFromDN(entry *ldap.Entry, cfg Config) (OUnames []string) {
	parsedDN, err := ldap.ParseDN(entry.DN)
	if err != nil {
		log.Fatal(err)
	}
	for _, o := range parsedDN.RDNs {
		if o.Attributes[0].Type == "OU" {
			ou := o.Attributes[0].Value
			if ou != cfg.UserBaseOU {
				OUnames = append(OUnames, ou)
			}
		}
	}
	return OUnames
}
