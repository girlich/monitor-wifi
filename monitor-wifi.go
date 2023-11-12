package main

import (
	"bufio"
	"crypto/md5"
	"crypto/tls" // new
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
	// _ "net/http/pprof"
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
	Port     int      `yaml:"port"`
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

type OmadaWebLoginResponse struct {
	Error          int                    `json:"errorCode"`
	Message        string                 `json:"msg"`
	Result         OmadaWebLoginResult    `json:"result"`
}

type OmadaWebLoginResult struct {
	OmadacId      []string                `json:"omadacId"`
	Token         string                  `json:"token"`
}

type OmadaWebSitesResponse struct {
	Error          int                    `json:"errorCode"`
	Message        string                 `json:"msg"`
	Result         OmadaWebSitesResult    `json:"result"`
}

type OmadaWebSitesResult struct {
	TotalRows     int                     `json:"totalRows"`
	CurrentPage   int                     `json:"currentPage"`
	CurrentSize   int                     `json:"currentSize"`
	Data          []OmadaWebSite          `json:"data"`
}

type OmadaWebSite struct {
	Id            string                  `json:"id"`
	Name          string                  `json:"name"`
	Type          int                     `json:"type"`
}

type OmadaWebClientsResponse struct {
	Error          int                    `json:"errorCode"`
	Message        string                 `json:"msg"`
	Result         OmadaWebClientsResult  `json:"result"`
}

type OmadaWebClientsResult struct {
	TotalRows     int                     `json:"totalRows"`
	CurrentPage   int                     `json:"currentPage"`
	CurrentSize   int                     `json:"currentSize"`
	Data          []OmadaWebClientData    `json:"data"`
	ClientStat    OmadaWebClientStat      `json:"clientStat"`
}

type OmadaWebClientData struct {
	MAC           string                  `json:"mac"`
	Name          string                  `json:"name"`
	DeviceType    string                  `json:"deviceType"`
	IP            string                  `json:"IP"`
	ConnectType   int                     `json:"connectType"`
	ConnectDevType string                 `json:"connectDevType"`
	ConnectedToWirelessRouter bool        `json:"connectedToWirelessRouter"`
	Wireless      bool                    `json:"wireless"`
	SSID          string                  `json:"ssid"`
	SignalLevel   int                     `json:"signalLevel"`
	HealthScore   int                     `json:"healthScore"`
	SignalRank    int                     `json:"signalRank"`
	WifiMode      int                     `json:"wifiMode"`
	ApName        string                  `json:"apName"`
	ApMac         string                  `json:"apMac"`
	RadioId       int                     `json:"radioId"`
	Channel       int                     `json:"channel"`
	RxRate        int                     `json:"rxRate"`
	TxRate        int                     `json:"txRate"`
	PowerSave     bool                    `json:"powerSave"`
	RSSI          int                     `json:"rssi"`
	Snr           int                     `json:"snr"`
	Activity      int                     `json:"activity"`
	TrafficDown   int                     `json:"trafficDown"`
	TrafficUp     int                     `json:"trafficUp"`
	Uptime        int                     `json:"uptime"`
	LastSeen      int                     `json:"lastSeen"`
	AuthStatus    int                     `json:"authStatus"`
	Guest         bool                    `json:"guest"`
	Active        bool                    `json:"active"`
	Manager       bool                    `json:"manager"`
	DownPacket    int                     `json:"downPacket"`
	UpPacket      int                     `json:"upPacket"`
	Support5G2    bool                    `json:"support5g2"`
	MultiLink     []OmadaWebMultiLink     `json:"multiLink"`
}

type OmadaWebMultiLink struct {
	RadioId       int                     `json:"radioId"`
	WifiMode      int                     `json:"wifiMode"`
	Channel       int                     `json:"channel"`
	RxRate        int                     `json:"rxRate"`
	TxRate        int                     `json:"txRate"`
	PowerSave     bool                    `json:"powerSave"`
	RSSI          int                     `json:"rssi"`
	Snr           int                     `json:"snr"`
	SignalLevel   int                     `json:"signalLevel"`
	SignalRank    int                     `json:"signalRank"`
	UpPacket      int                     `json:"upPacket"`
	DownPacket    int                     `json:"downPacket"`
	TrafficDown   int                     `json:"trafficDown"`
	TrafficUp     int                     `json:"trafficUp"`
	Activity      int                     `json:"activity"`
	SignalLevelAndRank  int               `json:"signalLevelAndRank"`
}

type OmadaWebClientStat struct {
	Total            int                  `json:"total"`
	Wireless         int                  `json:"wireless"`
	Wired            int                  `json:"wired"`
	Num2G            int                  `json:"num2g"`
	Num5G            int                  `json:"num5g"`
	Num6G            int                  `json:"num6g"`
	NumUser          int                  `json:"numUser"`
	NumGuest         int                  `json:"numGuest"`
	NumWirelessUser  int                  `json:"numWirelessUser"`
	NumWirelessGuest int                  `json:"numWirelessGuest"`
	Num2GUser        int                  `json:"num2gUser"`
	Num5GUser        int                  `json:"num5gUser"`
	Num6GUser        int                  `json:"num6gUser"`
	Num2GGuest       int                  `json:"num2gGuest"`
	Num5GGuest       int                  `json:"num5gGuest"`
	Num6GGuest       int                  `json:"num6gGuest"`
	Poor             int                  `json:"poor"`
	Fair             int                  `json:"fair"`
	NoData           int                  `json:"noData"`
	Good             int                  `json:"good"`
}

type OmadaWebStatusClientUser struct {
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
	ActiveTime int64     `yaml:"ActiveTime"`
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
	// Create a new client
	client := &http.Client{
		Jar: jar,
	}
	// Get a first response
	resp1, err := client.Get(u.String())
	if err != nil {
		log.Fatal(err)
	}
	defer resp1.Body.Close()

	// Prepare form data
	v1 := url.Values{}
	v1.Set("username", credentials.User)
	v1.Set("password", GetMD5Hash(credentials.Password))

	// Now POST with username and hashed password
	resp2, err := client.PostForm(u.String(), v1)
	if err != nil {
		log.Fatal(err)
	}
	defer resp2.Body.Close()

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
	resp3, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// Decode the JSON document
	json.NewDecoder(resp3.Body).Decode(clients)
	defer resp3.Body.Close()
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

		// ActiveTime converted to seconds
		var day, hour, min, sec int64
		_, err = fmt.Sscanf(clients.Data[i].ActiveTime, "%d days %d:%d:%d",
			&day, &hour, &min, &sec)
		nc.ActiveTime = sec + 60 * (min + 60 * (hour + 24 * day))

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
		nc.ActiveTime = int64(iw.ActiveTime)
		nc.Upstream = credentials.Host
		nc.WiFi.Radio = 0 // TODO: my raspi can only 2.4 GHz
		nc.WiFi.RSSI = iw.RSSI
		nc.WiFi.Rate = iw.Rate

		*networkClients = append(*networkClients, nc)
	}
}

func omadaweb_get(credentials *Credential, clients *OmadaWebClientsResponse) {
	// Create a new cookie jar
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	// Create a new Transport, ignore the TLS certificate as Omada runs internally only and will never have a valid TLS certificate.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// Create a new client with these things attached
	client := &http.Client{
		Jar: jar,
		Transport: transport,
	}




	// Login
	u, err := url.Parse(fmt.Sprintf("https://%s:%d/api/v2/login", credentials.Host, credentials.Port))
	if err != nil {
		log.Fatal(err)
	}
	var rawJsonData = []byte(`{
		"username": "%s",
		"password": "%s"
	}`)
	// A POST request to the login URL with the credential given
	request, err := http.NewRequest(
			http.MethodPost,
			u.String(),
			strings.NewReader(fmt.Sprintf(string(rawJsonData), credentials.User, credentials.Password)))
	resp1, err := client.Do(request)
	if err != nil {
		log.Fatal(err)
	}
	var omadaWebLoginResponse OmadaWebLoginResponse
	json.NewDecoder(resp1.Body).Decode(&omadaWebLoginResponse)
	defer resp1.Body.Close()

	fmt.Printf("token: %s\n", omadaWebLoginResponse.Result.Token)
	for _, omadacId := range omadaWebLoginResponse.Result.OmadacId {
		fmt.Printf("id: %s\n", omadacId)
	}
	omadacId := omadaWebLoginResponse.Result.OmadacId[0] // TODO loop over all IDs and combine the results




	// List of sites
	u, err = url.Parse(fmt.Sprintf("https://%s:%d/%s/api/v2/user/sites", credentials.Host, credentials.Port, omadacId))
	if err != nil {
		log.Fatal(err)
	}
	request, err = http.NewRequest(
			http.MethodGet,
			u.String(),
			strings.NewReader(""))
	request.Header.Add("Referer", fmt.Sprintf("https://%s:%d/%s/login", credentials.Host, credentials.Port, omadacId))
	request.Header.Add("Csrf-Token", omadaWebLoginResponse.Result.Token)
	resp2, err := client.Do(request)
	if err != nil {
		log.Fatal(err)
	}
	var omadaWebSitesResponse OmadaWebSitesResponse
	json.NewDecoder(resp2.Body).Decode(&omadaWebSitesResponse)
	defer resp2.Body.Close()

	for _, site := range omadaWebSitesResponse.Result.Data {
		fmt.Printf("site id: %s\n", site.Id)
	}
	// siteId := omadaWebSitesResponse.Result.Data[0].Id // TODO loop over all sites and combine the results
}

func omadaweb_to_network(credentials *Credential, omadawebClients *OmadaWebClientsResponse, networkClients *[]NetworkClient) {

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
		case "omadaweb":
			var Data OmadaWebClientsResponse
			omadaweb_get(&credentials[i], &Data)
			omadaweb_to_network(&credentials[i], &Data, NetworkClients)
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
			"mac",
			"upstream"},
		nil,
	)

	wifiDownloadBytesDesc = prometheus.NewDesc(
		"wifi_download_bytes",
		"Total downloaded bytes by the host",
		[]string{
			"mac",
			"upstream"},
		nil,
	)

	wifiActiveTimeDesc = prometheus.NewDesc(
		"wifi_active_time",
		"Total time host is connected to upstream",
		[]string{
			"mac",
			"upstream"},
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
		nc.Upstream,
		)
		ch <- prometheus.MustNewConstMetric(
		wifiDownloadBytesDesc,
		prometheus.CounterValue,
		float64(nc.Down),
		nc.MAC,
		nc.Upstream,
		)
		ch <- prometheus.MustNewConstMetric(
		wifiActiveTimeDesc,
		prometheus.CounterValue,
		float64(nc.ActiveTime),
		nc.MAC,
		nc.Upstream,
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
