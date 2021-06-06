all:

wificlients: wificlients.go
	go build $<

