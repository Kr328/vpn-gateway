.PHONY: build

build: vpn-gateway.zip

vpn-gateway.zip: module.prop service.sh
	zip vpn-gateway.zip module.prop service.sh

clean:
	rm -rf vpn-gateway.zip
