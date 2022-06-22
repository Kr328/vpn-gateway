.PHONY: build

build: vpn-gateway.zip

vpn-gateway.zip: META-INF module.prop service.sh
	zip -r vpn-gateway.zip META-INF module.prop service.sh

clean:
	rm -rf vpn-gateway.zip
