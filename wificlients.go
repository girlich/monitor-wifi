package main

import (
    "bytes"
    "crypto/md5"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net"
    "net/http"
    "net/http/cookiejar"
    "net/url"
    "os"
    "sort"
    "strings"

    "gopkg.in/yaml.v2"
)

func GetMD5Hash(text string) string {
   hash := md5.Sum([]byte(text))
   return strings.ToUpper(hex.EncodeToString(hash[:]))
}

type Credential struct {
    Type     string `yaml:"type"`
    Host     string `yaml:"host"`
    User     string `yaml:"user"`
    Password string `yaml:"password"`
    Command  string `yaml:"command"`
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

type WiFiParam struct {
    Radio      int    `yaml:"Radio"`
    RSSI       int    `yaml:"RSSI"`
    Rate       string `yaml:"Rate"`
}

type NetworkClient struct {
    Hostname   string `yaml:"hostname"`
    MAC        string `yaml:"MAC"`
    IP         string `yaml:"IP"`
    Down       int    `yaml:"Down"`
    Up         int    `yaml:"Up"`
    ActiveTime string `yaml:"ActiveTime"`
    LinkType   string `yaml:"linktype"`
    Upstream   string `yaml:"Upstream"`
    WiFi       WiFiParam `yaml:"WiFi,omitempty"`
}

func eap225_get(credentials *Credential, clients *Eap225StatusClientUsers) {
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

func eap225_to_network(credentials *Credential, clients *Eap225StatusClientUsers, networkClients *[]NetworkClient) {
  for i, _ := range clients.Data {
    var nc NetworkClient

    // Copy IP verbatim
    nc.IP = clients.Data[i].IP

    // Get canonical hostname from IP address
    names, err := net.LookupAddr(nc.IP)
    if err != nil {
      nc.Hostname = "unknown host"
    } else {
      nc.Hostname = names[0]
      if strings.HasSuffix(nc.Hostname, ".") {
        nc.Hostname = nc.Hostname[:len(nc.Hostname)-1]
      }
    }

    // Normalize MAC
    nc.MAC = strings.Replace(strings.ToLower(clients.Data[i].MAC), "-", ":", 5)

    // Linktype is WiFi
    nc.LinkType = "IEEE802_11"

    nc.WiFi.Radio = clients.Data[i].Radio
    nc.WiFi.RSSI = clients.Data[i].RSSI
    nc.WiFi.Rate = clients.Data[i].Rate

    // Download bytes
    nc.Down = clients.Data[i].Down

    // Upload bytes
    nc.Up = clients.Data[i].Up

    // Upstream is the Access Point
    nc.Upstream = credentials.Host

    // TODO: ActiveTime must be converted to seconds
    nc.ActiveTime = clients.Data[i].ActiveTime

    *networkClients = append(*networkClients, nc)
  }
}

func main() {
  // Read configuration with AP credentials
  byteValue, err := ioutil.ReadAll(os.Stdin)
  if err != nil {
    fmt.Println(err)
  }

  var credentials []Credential
  yaml.Unmarshal(byteValue, &credentials)

  var NetworkClients []NetworkClient
  for i := 0 ; i<len(credentials) ; i++ {
    if credentials[i].Type == "eap225" {
      var Data Eap225StatusClientUsers
      eap225_get(&credentials[i],&Data)
      eap225_to_network(&credentials[i], &Data, &NetworkClients)
    }
  }

  // sort NetworkClients according to the IP
  sort.Slice(
    NetworkClients,
    func(i, j int) bool {
      return bytes.Compare(
          net.ParseIP(NetworkClients[i].IP), net.ParseIP(NetworkClients[j].IP))<0
    })

  networkClientsB, _ := yaml.Marshal(&NetworkClients)
  fmt.Println(string(networkClientsB))
}

