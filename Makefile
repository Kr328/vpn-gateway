.PHONY: build

build: vpn-gateway.zip

vpn-gateway.zip: META-INF module.prop service.sh
	rm -rf vpn-gateway.zip
	zip -r vpn-gateway.zip META-INF module.prop service.sh

clean:
	rm -rf vpn-gateway.zip
