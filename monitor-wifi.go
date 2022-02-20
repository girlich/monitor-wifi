package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v2"
)

func GetMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return strings.ToUpper(hex.EncodeToString(hash[:]))
}

type Credential struct {
	Type     string   `yaml:"type"`
	Host     string   `yaml:"host"`
	User     string   `yaml:"user"`
	Password string   `yaml:"password"`
	Command  []string `yaml:"command"`
}

type Eap225StatusClientUsers struct {
	Error   int                      `yaml:"error"`
	Success bool                     `yaml:"success"`
	Timeout string                   `yaml:"timeout"`
	Data    []Eap225StatusClientUser `yaml:"data"`
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
	Down              int64  `yaml:"Down"`
	Up                int64  `yaml:"Up"`
	ActiveTime        string `yaml:"ActiveTime"`
	Limit             int    `yaml:"limit"`
	LimitUpload       int    `yaml:"limit_upload"`
	LimitUploadUnit   int    `yaml:"limit_upload_unit"`
	LimitDownload     int    `yaml:"limit_download"`
	LimitDownloadUnit int    `yaml:"limit_download_unit"`
}

type IwStationDump struct {
	MAC            string
	Interface      string
	InactiveTimeMs int
	Up             int64
	UpPackets      int
	Down           int64
	DownPackets    int
	DownErrors     int
	RSSI           int
	Rate           string
	UpRate         string
	Authorized     bool
	Authenticated  bool
	Associated     bool
	WMM_WME        bool
	TDLS_peer      bool
	DTIM_period    int
	BeaconInterval int
	ShortSlotTime  bool
	ActiveTime     int
}

type WiFiParam struct {
	Radio int    `yaml:"Radio"`
	RSSI  int    `yaml:"RSSI"`
	Rate  string `yaml:"Rate"`
}

type NetworkClient struct {
	Hostname   string    `yaml:"hostname,omitempty"`
	MAC        string    `yaml:"MAC"`
	IP         string    `yaml:"IP,omitempty"`
	Down       int64     `yaml:"Down"`
	Up         int64     `yaml:"Up"`
	ActiveTime string    `yaml:"ActiveTime"`
	LinkType   string    `yaml:"linktype"`
	Upstream   string    `yaml:"Upstream"`
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
	client := &http.Client{
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
	req, err := http.NewRequest("GET", "http://"+credentials.Host+"/data/status.client.user.json", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Prepare query data
	q := req.URL.Query()
	q.Add("operation", "load")
	//  q.Add("_","1588366765131")
	req.URL.RawQuery = q.Encode()
	req.Header.Add("Referer", "http://"+credentials.Host+"/")

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

func iw_get(credentials *Credential, clients *[]IwStationDump) {
	cmd := exec.Command(credentials.Command[0], credentials.Command[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	cmd.Start()
	buf := bufio.NewReader(stdout)
	var isd *IwStationDump = nil
	reMAC := regexp.MustCompile(`Station ([0-9a-f:]{17}) \(on `)
	reUp := regexp.MustCompile(`rx bytes:\s+(\d+)`)
	reDown := regexp.MustCompile(`tx bytes:\s+(\d+)`)
	reActiveTime := regexp.MustCompile(`connected time:\s+(\d+)`)
	reRSSI := regexp.MustCompile(`signal:\s+(-\d+)`)
	reRate := regexp.MustCompile(`rx bitrate:\s+(\d+\.\d+)`)
	for {
		line, _, err := buf.ReadLine()
		if err == io.EOF {
			break
		}
		lineS := string(line)
		// fmt.Printf(">>%s<<\n", lineS)
		res := reMAC.FindStringSubmatch(lineS)
		if res != nil {
			if isd != nil {
				// store the old content
				*clients = append(*clients, *isd)
			}
			// get new stoagre
			isd = &IwStationDump{}
			isd.MAC = res[1]
		}
		res = reUp.FindStringSubmatch(lineS)
		if res != nil {
			isd.Up, _ = strconv.ParseInt(res[1], 10, 64)
		}
		res = reDown.FindStringSubmatch(lineS)
		if res != nil {
			isd.Down, _ = strconv.ParseInt(res[1], 10, 64)
		}
		res = reActiveTime.FindStringSubmatch(lineS)
		if res != nil {
			isd.ActiveTime, _ = strconv.Atoi(res[1])
		}
		res = reRSSI.FindStringSubmatch(lineS)
		if res != nil {
			isd.RSSI, _ = strconv.Atoi(res[1])
		}
		res = reRate.FindStringSubmatch(lineS)
		if res != nil {
			isd.Rate = res[1]
		}
	}
	// append last one
	if isd != nil {
		*clients = append(*clients, *isd)
	}
}

func iw_to_network(credentials *Credential, iwClients *[]IwStationDump, networkClients *[]NetworkClient) {
	for _, iw := range *iwClients {
		var nc NetworkClient
		nc.MAC = iw.MAC
		nc.Up = iw.Up
		nc.Down = iw.Down
		nc.LinkType = "IEEE802_11"
		nc.ActiveTime = strconv.Itoa(iw.ActiveTime)
		nc.Upstream = credentials.Host
		nc.WiFi.Radio = 0 // TODO: my raspi can only 2.4 GHz
		nc.WiFi.RSSI = iw.RSSI
		nc.WiFi.Rate = iw.Rate

		*networkClients = append(*networkClients, nc)
	}
}

func CollectNetworkClients(credentials []Credential, NetworkClients *[]NetworkClient) {
	for i := 0; i < len(credentials); i++ {
		switch credentials[i].Type {
		case "eap225":
			var Data Eap225StatusClientUsers
			eap225_get(&credentials[i], &Data)
			eap225_to_network(&credentials[i], &Data, NetworkClients)
		case "iw":
			var Data []IwStationDump
			iw_get(&credentials[i], &Data)
			iw_to_network(&credentials[i], &Data, NetworkClients)
		default:
			fmt.Fprintf(os.Stderr, "unknown AP type: %s\n", credentials[i].Type)
		}
	}
}

type WifiCollector struct {
	Credentials []Credential
}

var (
	wifiUploadBytesDesc = prometheus.NewDesc(
		"wifi_upload_bytes",
		"Total uploaded bytes by the host",
		[]string{
			"mac"},
		nil,
	)

	wifiDownloadBytesDesc = prometheus.NewDesc(
		"wifi_download_bytes",
		"Total downloaded bytes by the host",
		[]string{
			"mac"},
		nil,
	)
)

func (wc WifiCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(wc, ch)
}

func (wc WifiCollector) Collect(ch chan<- prometheus.Metric) {
	var NetworkClients []NetworkClient
	CollectNetworkClients(wc.Credentials, &NetworkClients)

	for _, nc := range NetworkClients {
		ch <- prometheus.MustNewConstMetric(
		wifiUploadBytesDesc,
		prometheus.CounterValue,
		float64(nc.Up),
		nc.MAC,
		)
		ch <- prometheus.MustNewConstMetric(
		wifiDownloadBytesDesc,
		prometheus.CounterValue,
		float64(nc.Down),
		nc.MAC,
		)
	}
}

func prometheusListen(listen string, credentials []Credential) {
	registry := prometheus.NewRegistry()
	fmt.Println("listen on " + listen)
	wc := WifiCollector{Credentials: credentials}
	registry.MustRegister(wc)
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	http.Handle("/metrics", handler)
	log.Fatal(http.ListenAndServe(listen, nil))
}

func main() {
	var listen string
	flag.StringVar(&listen, "listen", "", "thing to listen on (like :1234) for Prometheus requests")
	flag.Parse()

	// Read configuration with AP credentials
	byteValue, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Println(err)
	}

	var credentials []Credential
	yaml.Unmarshal(byteValue, &credentials)

	if listen == "" {
		var NetworkClients []NetworkClient
		CollectNetworkClients(credentials, &NetworkClients)
		networkClientsB, _ := yaml.Marshal(&NetworkClients)
		fmt.Println(string(networkClientsB))
	} else {
		prometheusListen(listen, credentials)
	}

}
