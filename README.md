# zoraxy-crowdsec-bouncer

WIP crowdsec integration for the zoraxy reverse proxy

References:

- [Zoraxy Plugin Documentation](https://zoraxy.aroz.org/plugins/html/)
- [Crowdsec Documentation](https://docs.crowdsec.net/)
- [go-cs-bouncer](https://github.com/crowdsecurity/go-cs-bouncer)

Since this needs to look at all incoming requests, it is implemented as a [Dynamic Capture Plugin](https://zoraxy.aroz.org/plugins/html/3.%20Basic%20Examples/4.%20Dynamic%20Capture%20Example.html).

For now, it uses a live bouncer, which queries the Crowdsec API for decisions on each request. However, in the future, it should be possible to use a static bouncer that stores deicisions in an in-memory cache or file and only queries the Crowdsec API for updates periodically.

## Installation

<https://zoraxy.aroz.org/plugins/html/1.%20Introduction/3.%20Installing%20Plugin.html>

### From GitHub Actions Artifacts

Create a directory for the plugin if it doesn't exist:

```bash
mkdir -p /opt/zoraxy/plugins/zoraxy_crowdsec_bouncer
```

Then, copy the link to the latest binary from the [releases page](https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer/releases) and use `wget` to download it to the `zoraxy_crowdsec_bouncer` directory:

```bash
cd /opt/zoraxy/plugins/zoraxycrowdsecbouncer
# wget <LINK_TO_LATEST_BINARY>
wget https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer/releases/download/v1.0.0/zoraxycrowdsecbouncer
chmod +x zoraxycrowdsecbouncer
```

Do the same for the `config.yaml` file:

```bash
wget https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer/releases/download/v1.0.0/config.yaml
```

### From Source

Clone the repository inside the Zoraxy plugins directory, then build the plugin:

```bash
cd /opt/zoraxy/plugins
git clone https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer.git zoraxycrowdsecbouncer

cd zoraxycrowdsecbouncer
go build -o zoraxycrowdsecbouncer.so
chmod +x zoraxycrowdsecbouncer.so
```

## Configuration

TODO: implement a way to configure the bouncer via the web UI.

in the same directory as the plugin, there should be a `config.yaml` file with some default configuration. Fill in the values as needed.

```yaml
api_key: YOUR_API_KEY
agent_url: http://127.0.0.1:8080 # for example
debug: false
```

You can get the API key by running the following command:

```bash
sudo cscli bouncers add zoraxy-crowdsec-bouncer
```
