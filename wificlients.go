package main

import (
    "crypto/md5"
    "encoding/hex"
    "fmt"
    "io"
    "io/ioutil"
    "log"
    "net/http"
    "net/http/cookiejar"
    "net/url"
    "os"
    "strings"

    "gopkg.in/yaml.v2"
)

func GetMD5Hash(text string) string {
   hash := md5.Sum([]byte(text))
   return strings.ToUpper(hex.EncodeToString(hash[:]))
}

type AccessPoints struct {
  Eap225s []Eap225 `yaml:"eap225"`
}

type Eap225 struct {
    Host     string `yaml:"host"`
    User     string `yaml:"user"`
    Password string `yaml:"password"`
}

func eap225_get(credentials *Eap225) {
  // Parse URL
  u, err := url.Parse("http://" + credentials.Host + "/")
  if err != nil {
    log.Fatal(err)
  }

  // Create a new cookie jar
  jar, err := cookiejar.New(nil)
  if err != nil {
    log.Fatal(err)
  }
  // Create a now client
  client := &http.Client {
    Jar: jar,
  }
  // Get a first response
  resp, err := client.Get(u.String())
  if err != nil {
    log.Fatal(err)
  }
  // Read it
  //content, err := io.ReadAll(resp.Body)
  //resp.Body.Close()
  //if err != nil {
  //  log.Fatal(err)
  //}
  // Print it
  //fmt.Printf("%s", content)
  // Print cookies
  for _, cookie := range jar.Cookies(u) {
    fmt.Printf("1  %s: %s\n", cookie.Name, cookie.Value)
  }

  // Prepare form data
  v1 := url.Values{}
  v1.Set("username", credentials.User)
  v1.Set("password", GetMD5Hash(credentials.Password))

  // Now POST with username and hashed password
  resp, err = client.PostForm(u.String(), v1)
  if err != nil {
    log.Fatal(err)
  }

  // Read content
  //content, err = io.ReadAll(resp.Body)
  //resp.Body.Close()
  //if err != nil {
  //  log.Fatal(err)
 // }
 // fmt.Printf("%s", content)

  // Print cookies
  for _, cookie := range jar.Cookies(u) {
    fmt.Printf("2  %s: %s\n", cookie.Name, cookie.Value)
  }

  // Create an empty request
  req, err := http.NewRequest("GET", "http://" + credentials.Host + "/data/status.client.user.json", nil)
  if err != nil {
    log.Fatal(err)
  }

  // Prepare query data
  q := req.URL.Query()
  q.Add("operation","load")
  q.Add("_","1588366765131")
  req.URL.RawQuery = q.Encode()
  req.Header.Add("Referer", "http://" + credentials.Host + "/")
  fmt.Println(req.URL.String())

  // Do it
  resp, err = client.Do(req)

  // Read content
  content, err := io.ReadAll(resp.Body)
  resp.Body.Close()
  if err != nil {
    log.Fatal(err)
  }
  // Print it
  fmt.Printf("%s", content)
}

func main() {
  byteValue, err := ioutil.ReadAll(os.Stdin)
  if err != nil {
    fmt.Println(err)
  }
  var accesspoints AccessPoints
  yaml.Unmarshal(byteValue, &accesspoints)
  for i := 0 ; i<len(accesspoints.Eap225s) ; i++ {
    eap225_get(&accesspoints.Eap225s[i])
  }
}

