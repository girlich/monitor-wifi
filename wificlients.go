package main

import (
    "crypto/md5"
    "encoding/hex"
    "encoding/json"
    "fmt"
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

type Credentials struct {
  Eap225s []Eap225Credential `yaml:"eap225"`
}

type Eap225Credential struct {
    Host     string `yaml:"host"`
    User     string `yaml:"user"`
    Password string `yaml:"password"`
}

type MultiEap225StatusClientUsers struct {
  AccessPoints []AccessPoint `yaml:"AccessPoint"`
}

type AccessPoint struct {
  Name string                  `yaml:"name"`
  Data Eap225StatusClientUsers `yaml:"clients"`
}

type Eap225StatusClientUsers struct {
    Error    int                      `yaml:"error"`
    Success  bool                     `yaml:"success"`
    Timeout  string                   `yaml:"timeout"`
    Data     []Eap225StatusClientUser `yaml:"data"`
}

type Eap225StatusClientUser struct {
    Key               int    `yaml:"key"`
    Hostname          string `yaml:"hostname"`
    Radio             int    `yaml:"Radio"`
    MAC               string `yaml:"MAC"`
    IP                string `yaml:"IP"`
    SSID              string `yaml:"SSID"`
    RSSI              int    `yaml:"RSSI"`
    Rate              string `yaml:"Rate"`
    Down              int    `yaml:"Down"`
    Up                int    `yaml:"Up"`
    ActiveTime        string `yaml:"ActiveTime"`
    Limit             int    `yaml:"limit"`
    LimitUpload       int    `yaml:"limit_upload"`
    LimitUploadUnit   int    `yaml:"limit_upload_unit"`
    LimitDownload     int    `yaml:"limit_download"`
    LimitDownloadUnit int    `yaml:"limit_download_unit"`
}

func eap225_get(credentials *Eap225Credential, clients *Eap225StatusClientUsers) {
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

  // Prepare form data
  v1 := url.Values{}
  v1.Set("username", credentials.User)
  v1.Set("password", GetMD5Hash(credentials.Password))

  // Now POST with username and hashed password
  resp, err = client.PostForm(u.String(), v1)
  if err != nil {
    log.Fatal(err)
  }

  // Create an empty request
  req, err := http.NewRequest("GET", "http://" + credentials.Host + "/data/status.client.user.json", nil)
  if err != nil {
    log.Fatal(err)
  }

  // Prepare query data
  q := req.URL.Query()
  q.Add("operation","load")
//  q.Add("_","1588366765131")
  req.URL.RawQuery = q.Encode()
  req.Header.Add("Referer", "http://" + credentials.Host + "/")

  // Do it
  resp, err = client.Do(req)

  // Decode the JSON document
  json.NewDecoder(resp.Body).Decode(clients)

}

func main() {
  // Read configuration with AP credentials
  byteValue, err := ioutil.ReadAll(os.Stdin)
  if err != nil {
    fmt.Println(err)
  }
  var credentials Credentials
  yaml.Unmarshal(byteValue, &credentials)

  var multiEap225StatusClientUsers MultiEap225StatusClientUsers
  multiEap225StatusClientUsers.AccessPoints = make([]AccessPoint, len(credentials.Eap225s))
  for i := 0 ; i<len(credentials.Eap225s) ; i++ {
    multiEap225StatusClientUsers.AccessPoints[i].Name=credentials.Eap225s[i].Host
    eap225_get(&credentials.Eap225s[i],&(multiEap225StatusClientUsers.AccessPoints[i].Data))
  }

  multiEap225StatusClientUsersB, _ := yaml.Marshal(&multiEap225StatusClientUsers)
    fmt.Println(string(multiEap225StatusClientUsersB))
}

