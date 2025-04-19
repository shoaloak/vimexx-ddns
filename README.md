# Dynamic DNS Updater for Vimexx/WHMC

Automatically update DNS records for your domain with your current public IP address. Perfect for home servers with dynamic IPs, allowing you to maintain consistent access via a subdomain of your choice.

## Features

- Updates A records (IPv4) and AAAA records (IPv6) for your domain and subdomains
- Toggleable IPv4 and IPv6 support
- Configurable TTL (Time To Live) values
- Automatic detection of your public IP addresses

## Global Configuration

The script behavior can be modified through the following global variables in `src/ddns.py`:

```python
TTL = str(60*60)  # 1 hour TTL (in seconds)
ENABLE_IPV4 = True  # Toggle IPv4 support
ENABLE_IPV6 = True  # Toggle IPv6 support
```

## Setup

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/vimexx-ddns /opt/vimexx-ddns
   cd /opt/vimexx-ddns
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure your credentials:
   ```
   cp config/credentials_example.json config/credentials.json
   vi config/credentials.json
   ```
   
   Add your WHMC credentials:
   ```json
   {
     "client_id": "your_client_id",
     "client_key": "your_client_key",
     "email": "your_email",
     "password": "your_password",
     "domain": "yourdomain.com"
   }
   ```

4. Configure your subdomains:
   ```
   cp config/subdomains_example.json config/subdomains.json
   vi config/subdomains.json
   ```
   
   Add your subdomains:
   ```json
   ["www", "ftp"]
   ```

## Usage

Run the script manually:
```
python src/ddns.py
```

For automatic updates, set up a cron job:
```
crontab -e
```

Add this line to run the script every hour:
```
0 * * * * python3 /opt/vimexx-ddns/src/ddns.py
```

## Requirements

- Python 3.6+
- `requests` library

## License

MIT License