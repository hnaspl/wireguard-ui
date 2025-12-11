![](https://github.com/ngoduykhanh/wireguard-ui/workflows/wireguard-ui%20build%20release/badge.svg)

# wireguard-ui

A web user interface to manage your WireGuard setup.

## Features

- Friendly UI
- Authentication
- Manage extra client information (name, email, etc.)
- Retrieve client config using QR code / file / email / Telegram
- **Site-to-Site VPN** - Connect multiple WireGuard networks together
- **Firewall Rules Management** - Per-client access control with whitelist/blacklist support
- **Auto-generated PostUp/PostDown Scripts** - Automatic iptables rule generation for site-to-site setups

![wireguard-ui 0.3.7](https://user-images.githubusercontent.com/37958026/177041280-e3e7ca16-d4cf-4e95-9920-68af15e780dd.png)

## Run WireGuard-UI

> ⚠️The default username and password are `admin`. Please change it to secure your setup.

### Using binary file

Download the binary file from the release page and run it directly on the host machine

```
./wireguard-ui
```

### Using docker compose

The [examples/docker-compose](examples/docker-compose) folder contains example docker-compose files.
Choose the example which fits you the most, adjust the configuration for your needs, then run it like below:

```
docker-compose up
```

## Environment Variables

| Variable                      | Description                                                                                                                                                                                                                                                                         | Default                            |
|-------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------|
| `BASE_PATH`                   | Set this variable if you run wireguard-ui under a subpath of your reverse proxy virtual host (e.g. /wireguard)                                                                                                                                                                      | N/A                                |
| `BIND_ADDRESS`                | The addresses that can access to the web interface and the port, use unix:///abspath/to/file.socket for unix domain socket.                                                                                                                                                         | 0.0.0.0:80                         |
| `SESSION_SECRET`              | The secret key used to encrypt the session cookies. Set this to a random value                                                                                                                                                                                                      | N/A                                |
| `SESSION_SECRET_FILE`         | Optional filepath for the secret key used to encrypt the session cookies. Leave `SESSION_SECRET` blank to take effect                                                                                                                                                               | N/A                                |
| `SESSION_MAX_DURATION`        | Max time in days a remembered session is refreshed and valid. Non-refreshed session is valid for 7 days max, regardless of this setting.                                                                                                                                            | 90                                 |
| `SUBNET_RANGES`               | The list of address subdivision ranges. Format: `SR Name:10.0.1.0/24; SR2:10.0.2.0/24,10.0.3.0/24` Each CIDR must be inside one of the server interfaces.                                                                                                                           | N/A                                |
| `WGUI_USERNAME`               | The username for the login page. Used for db initialization only                                                                                                                                                                                                                    | `admin`                            |
| `WGUI_PASSWORD`               | The password for the user on the login page. Will be hashed automatically. Used for db initialization only                                                                                                                                                                          | `admin`                            |
| `WGUI_PASSWORD_FILE`          | Optional filepath for the user login password. Will be hashed automatically. Used for db initialization only. Leave `WGUI_PASSWORD` blank to take effect                                                                                                                            | N/A                                |
| `WGUI_PASSWORD_HASH`          | The password hash for the user on the login page. (alternative to `WGUI_PASSWORD`). Used for db initialization only                                                                                                                                                                 | N/A                                |
| `WGUI_PASSWORD_HASH_FILE`     | Optional filepath for the user login password hash. (alternative to `WGUI_PASSWORD_FILE`). Used for db initialization only. Leave `WGUI_PASSWORD_HASH` blank to take effect                                                                                                         | N/A                                |
| `WGUI_ENDPOINT_ADDRESS`       | The default endpoint address used in global settings where clients should connect to. The endpoint can contain a port as well, useful when you are listening internally on the `WGUI_SERVER_LISTEN_PORT` port, but you forward on another port (ex 9000). Ex: myvpn.dyndns.com:9000 | Resolved to your public ip address |
| `WGUI_FAVICON_FILE_PATH`      | The file path used as website favicon                                                                                                                                                                                                                                               | Embedded WireGuard logo            |
| `WGUI_DNS`                    | The default DNS servers (comma-separated-list) used in the global settings                                                                                                                                                                                                          | `1.1.1.1`                          |
| `WGUI_MTU`                    | The default MTU used in global settings                                                                                                                                                                                                                                             | `1450`                             |
| `WGUI_PERSISTENT_KEEPALIVE`   | The default persistent keepalive for WireGuard in global settings                                                                                                                                                                                                                   | `15`                               |
| `WGUI_FIREWALL_MARK`          | The default WireGuard firewall mark                                                                                                                                                                                                                                                 | `0xca6c`  (51820)                  |
| `WGUI_TABLE`                  | The default WireGuard table value settings                                                                                                                                                                                                                                          | `auto`                             |
| `WGUI_CONFIG_FILE_PATH`       | The default WireGuard config file path used in global settings                                                                                                                                                                                                                      | `/etc/wireguard/wg0.conf`          |
| `WGUI_LOG_LEVEL`              | The default log level. Possible values: `DEBUG`, `INFO`, `WARN`, `ERROR`, `OFF`                                                                                                                                                                                                     | `INFO`                             |
| `WG_CONF_TEMPLATE`            | The custom `wg.conf` config file template. Please refer to our [default template](https://github.com/ngoduykhanh/wireguard-ui/blob/master/templates/wg.conf)                                                                                                                        | N/A                                |
| `EMAIL_FROM_ADDRESS`          | The sender email address                                                                                                                                                                                                                                                            | N/A                                |
| `EMAIL_FROM_NAME`             | The sender name                                                                                                                                                                                                                                                                     | `WireGuard UI`                     |
| `SENDGRID_API_KEY`            | The SendGrid api key                                                                                                                                                                                                                                                                | N/A                                |
| `SENDGRID_API_KEY_FILE`       | Optional filepath for the SendGrid api key. Leave `SENDGRID_API_KEY` blank to take effect                                                                                                                                                                                           | N/A                                |
| `SMTP_HOSTNAME`               | The SMTP IP address or hostname                                                                                                                                                                                                                                                     | `127.0.0.1`                        |
| `SMTP_PORT`                   | The SMTP port                                                                                                                                                                                                                                                                       | `25`                               |
| `SMTP_USERNAME`               | The SMTP username                                                                                                                                                                                                                                                                   | N/A                                |
| `SMTP_PASSWORD`               | The SMTP user password                                                                                                                                                                                                                                                              | N/A                                |
| `SMTP_PASSWORD_FILE`          | Optional filepath for the SMTP user password. Leave `SMTP_PASSWORD` blank to take effect                                                                                                                                                                                            | N/A                                |
| `SMTP_AUTH_TYPE`              | The SMTP authentication type. Possible values: `PLAIN`, `LOGIN`, `NONE`                                                                                                                                                                                                             | `NONE`                             |
| `SMTP_ENCRYPTION`             | The encryption method. Possible values: `NONE`, `SSL`, `SSLTLS`, `TLS`, `STARTTLS`                                                                                                                                                                                                  | `STARTTLS`                         |
| `SMTP_HELO`                   | Hostname to use for the HELO message. smtp-relay.gmail.com needs this set to anything but `localhost`                                                                                                                                                                               | `localhost`                        |
| `TELEGRAM_TOKEN`              | Telegram bot token for distributing configs to clients                                                                                                                                                                                                                              | N/A                                |
| `TELEGRAM_ALLOW_CONF_REQUEST` | Allow users to get configs from the bot by sending a message                                                                                                                                                                                                                        | `false`                            |
| `TELEGRAM_FLOOD_WAIT`         | Time in minutes before the next conf request is processed                                                                                                                                                                                                                           | `60`                               |

### Defaults for server configuration

These environment variables are used to control the default server settings used when initializing the database.

| Variable                          | Description                                                                                   | Default         |
|-----------------------------------|-----------------------------------------------------------------------------------------------|-----------------|
| `WGUI_SERVER_INTERFACE_ADDRESSES` | The default interface addresses (comma-separated-list) for the WireGuard server configuration | `10.252.1.0/24` |
| `WGUI_SERVER_LISTEN_PORT`         | The default server listen port                                                                | `51820`         |
| `WGUI_SERVER_POST_UP_SCRIPT`      | The default server post-up script                                                             | N/A             |
| `WGUI_SERVER_POST_DOWN_SCRIPT`    | The default server post-down script                                                           | N/A             |

### Defaults for new clients

These environment variables are used to set the defaults used in `New Client` dialog.

| Variable                                    | Description                                                                                     | Default     |
|---------------------------------------------|-------------------------------------------------------------------------------------------------|-------------|
| `WGUI_DEFAULT_CLIENT_ALLOWED_IPS`           | Comma-separated-list of CIDRs for the `Allowed IPs` field. (default )                           | `0.0.0.0/0` |
| `WGUI_DEFAULT_CLIENT_EXTRA_ALLOWED_IPS`     | Comma-separated-list of CIDRs for the `Extra Allowed IPs` field. (default empty)                | N/A         |
| `WGUI_DEFAULT_CLIENT_USE_SERVER_DNS`        | Boolean value [`0`, `f`, `F`, `false`, `False`, `FALSE`, `1`, `t`, `T`, `true`, `True`, `TRUE`] | `true`      |
| `WGUI_DEFAULT_CLIENT_ENABLE_AFTER_CREATION` | Boolean value [`0`, `f`, `F`, `false`, `False`, `FALSE`, `1`, `t`, `T`, `true`, `True`, `TRUE`] | `true`      |

### PostUp/PostDown Scripts

Scripts are **automatically generated** when you click "Apply Config". Firewall rules from the UI are always integrated into these scripts.

| Variable                         | Description                                                                                      | Default              |
|----------------------------------|--------------------------------------------------------------------------------------------------|----------------------|
| `WGUI_POST_UP_SCRIPT_PATH`       | Path where PostUp script will be saved                                                           | `/etc/wireguard/postup.sh`   |
| `WGUI_POST_DOWN_SCRIPT_PATH`     | Path where PostDown script will be saved                                                         | `/etc/wireguard/postdown.sh` |
| `WGUI_LAN_ALL`                   | Local network ranges. Defines which networks can communicate with WireGuard peers                | `192.168.0.0/16`     |
| `WGUI_LAN_PROTECT`               | Protected IPs that WireGuard clients cannot access (e.g., router admin interface)                | `192.168.4.1/32`     |
| `WGUI_MASQ_OIF_PATTERN`          | Network interface pattern for NAT/masquerading to internet (e.g., `eth+` matches eth0, eth1)    | `eth+`               |

**Notes:**
- `WG_SUBNETS` is automatically calculated from `WGUI_SERVER_INTERFACE_ADDRESSES` and does not need to be configured separately
- Firewall rules configured in the UI are automatically integrated into the generated scripts
- Scripts include: INPUT chain rules, FORWARD chain management, protected IP blocking, MSS clamping, no-NAT for site-to-site, and internet masquerading

### Docker only

These environment variables only apply to the docker container.

| Variable              | Description                                                   | Default |
|-----------------------|---------------------------------------------------------------|---------|
| `WGUI_MANAGE_START`   | Start/stop WireGuard when the container is started/stopped    | `false` |
| `WGUI_MANAGE_RESTART` | Auto restart WireGuard when we Apply Config changes in the UI | `false` |

## Site-to-Site VPN Configuration

WireGuard-UI supports site-to-site VPN connections, allowing you to connect multiple WireGuard networks together.

### Setting Up a Site-to-Site Connection

1. Navigate to **Wireguard Clients** and click **New Client**
2. Enter a name for the remote site (e.g., "Remote Office" or "wg_friend")
3. Check the **"Site-to-Site Connection"** checkbox
4. Configure the peer:
   - **Endpoint**: Enter the remote site's public IP and port (e.g., `vpn.remotesite.com:51820`)
   - **Allowed IPs**: Enter the remote network ranges you want to access (e.g., `10.0.0.0/24`)
   - **Public Key**: Enter the remote site's public key
   - **PresharedKey** (optional): For additional security
   - **Persistent Keepalive**: Recommended for site-to-site (e.g., `25`)
5. Click **Submit**

### How It Works

When you enable **Site-to-Site Connection**:
- The client becomes a peer in your server's WireGuard configuration
- Your server will connect TO the remote site (not the other way around)
- Traffic is routed bidirectionally between your network and the remote network
- No NAT is applied to site-to-site traffic (preserving real IP addresses)
- MSS clamping is automatically configured to handle MTU issues

### Example Use Case

You have two sites:
- **Site A**: Your main office with network `192.168.1.0/24`
- **Site B**: Remote location with network `10.0.0.0/24`

On Site A's WireGuard-UI:
1. Create a site-to-site client for "Site B"
2. Set Endpoint to Site B's public IP
3. Set AllowedIPs to `10.0.0.0/24`
4. Add firewall rules (optional) to restrict which services Site B can access on your network

## Firewall Rules Management

Control which clients can access specific parts of your network with fine-grained firewall rules.

### Access Control Logic

- **Clients WITH firewall rules**: Only the traffic specified in firewall rules is allowed. All other traffic is blocked.
- **Clients WITHOUT firewall rules**: Full network access (default allow), respecting only the protected IP restrictions.

This enables flexible access control where you can:
- Give trusted clients full access (no firewall rules)
- Restrict site-to-site peers to specific services
- Limit mobile clients to only what they need

### Managing Firewall Rules

1. Navigate to **Settings** → **Firewall Rules**
2. Click **Add Rule** to create a new rule
3. Configure the rule:
   - **Client**: Select which client this rule applies to
   - **Allowed IP**: The destination IP or network (e.g., `192.168.1.10` or `192.168.1.0/24`)
   - **Allowed Port**: Port or port range (e.g., `443`, `80:443`, or `any`)
   - **Protocol**: TCP, UDP, or any
   - **Description**: Note about what this rule allows
   - **Enabled**: Toggle to enable/disable the rule
4. Click **Save**

### How Firewall Rules Work

Firewall rules are **automatically integrated** into PostUp/PostDown scripts when you click **Apply Config**:

1. Scripts are generated and saved to configured paths (default: `/etc/wireguard/postup.sh` and `/etc/wireguard/postdown.sh`)
2. Generated scripts include:
   - Base iptables rules for WireGuard traffic
   - **Your firewall rules from the UI automatically injected**
   - MSS clamping for MTU handling
   - No-NAT configuration for site-to-site VPNs
   - Protected IP blocking (e.g., router admin interface)
   - Internet masquerading for external traffic
3. Firewall rules are enforced using iptables FORWARD chain rules

**No configuration needed** - firewall rules always work once you apply config

### Environment Variables for Scripts

Configure these in **Global Settings**:

- **WG_SUBNETS**: Automatically calculated from your Wireguard Server interface addresses (no manual configuration needed)
- **LAN_ALL**: Your local network ranges (e.g., `192.168.0.0/16`)
- **LAN_PROTECT**: IPs to protect from WireGuard access (e.g., `192.168.4.1/32` for router admin)
- **MASQ_OIF_PATTERN**: Interface pattern for internet NAT (e.g., `eth+`)

These variables are automatically injected into the generated scripts.

### Example Scenarios

#### Scenario 1: Restricted Site-to-Site Connection
```
Client: "wg_friend" (site-to-site enabled)
Firewall Rules:
  - Allow 192.168.1.10 port 443 (HTTPS to web server)
  - Allow 192.168.1.20 port 22 (SSH to backup server)
Result: Friend can only access those two services, all other traffic blocked
```

#### Scenario 2: Mobile User with Limited Access
```
Client: "employee_phone"
Firewall Rules:
  - Allow 192.168.1.0/24 port 443 (Web services)
  - Allow 192.168.2.5 port 3389 (RDP to their workstation)
Result: Employee can access web services and their workstation only
```

#### Scenario 3: Trusted Admin
```
Client: "admin_laptop"
Firewall Rules: (none)
Result: Full network access except protected IPs
```

## Auto restart WireGuard daemon

WireGuard-UI only takes care of configuration generation. You can use systemd to watch for the changes and restart the
service. Following is an example:

### Using systemd

Create `/etc/systemd/system/wgui.service`

```bash
cd /etc/systemd/system/
cat << EOF > wgui.service
[Unit]
Description=Restart WireGuard
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl restart wg-quick@wg0.service

[Install]
RequiredBy=wgui.path
EOF
```

Create `/etc/systemd/system/wgui.path`

```bash
cd /etc/systemd/system/
cat << EOF > wgui.path
[Unit]
Description=Watch /etc/wireguard/wg0.conf for changes

[Path]
PathModified=/etc/wireguard/wg0.conf

[Install]
WantedBy=multi-user.target
EOF
```

Apply it

```sh
systemctl enable wgui.{path,service}
systemctl start wgui.{path,service}
```

### Using openrc

Create `/usr/local/bin/wgui` file and make it executable

```sh
cd /usr/local/bin/
cat << EOF > wgui
#!/bin/sh
wg-quick down wg0
wg-quick up wg0
EOF
chmod +x wgui
```

Create `/etc/init.d/wgui` file and make it executable

```sh
cd /etc/init.d/
cat << EOF > wgui
#!/sbin/openrc-run

command=/sbin/inotifyd
command_args="/usr/local/bin/wgui /etc/wireguard/wg0.conf:w"
pidfile=/run/${RC_SVCNAME}.pid
command_background=yes
EOF
chmod +x wgui
```

Apply it

```sh
rc-service wgui start
rc-update add wgui default
```

### Using Docker

Set `WGUI_MANAGE_RESTART=true` to manage Wireguard interface restarts.
Using `WGUI_MANAGE_START=true` can also replace the function of `wg-quick@wg0` service, to start Wireguard at boot, by
running the container with `restart: unless-stopped`. These settings can also pick up changes to Wireguard Config File
Path, after restarting the container. Please make sure you have `--cap-add=NET_ADMIN` in your container config to make
this feature work.

## Build

### Build docker image

Go to the project root directory and run the following command:

```sh
docker build --build-arg=GIT_COMMIT=$(git rev-parse --short HEAD) -t wireguard-ui .
```

or

```sh
docker compose build --build-arg=GIT_COMMIT=$(git rev-parse --short HEAD)
```

:information_source: A container image is available on [Docker Hub](https://hub.docker.com/r/ngoduykhanh/wireguard-ui)
which you can pull and use

```
docker pull ngoduykhanh/wireguard-ui
````

### Build binary file

Prepare the assets directory

```sh
./prepare_assets.sh
```

Then build your executable

```sh
go build -o wireguard-ui
```

## License

MIT. See [LICENSE](https://github.com/ngoduykhanh/wireguard-ui/blob/master/LICENSE).

## Support

If you like the project and want to support it, you can *buy me a coffee* ☕

<a href="https://www.buymeacoffee.com/khanhngo" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>
