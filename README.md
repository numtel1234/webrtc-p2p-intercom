# WebRTC P2P Internet Intercom

A WebRTC-based, P2P intercom with proper account auth, admin pages, and customizable sound profiles for each user.
This app provides similar functionality to a radio system, but without the physical hassle as you can use any device that can open a web browser to join into the network.

# Install and Usage
This repo contains the server, static assets, and example `.env` configs.


1. Install requirements
```bash
pip install -r requirements.txt
```
2. set up the `.env` file
```bash
mv .example.env .env
nano .env
```
Example settings in the .env file:

    # Admin credentials
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "***"

    # SQLite DB file location
    DB_FILE = "backend_db.db"

    # SSL certificate and key file locations for HTTPS
    CERT_FILE = "server.crt"
    CERT_KEY_FILE = "server.key"

    # Host and port for server
    HOST = "0.0.0.0"
    PORT = 8080
3. Set up a SSL certificate

Using [`mkcert`](https://mkcert.dev):
```bash
# this will generate <host>.pem and <host>-key.pem
mkcert <host>
```
Using [`openssl req`](https://docs.openssl.org/master/man1/openssl-req/):
```bash
openssl req -newkey rsa:4096 \
-x509 -sha256 -days 3650 -noenc \
-out server.crt -keyout server.key \
-addext "subjectAltName=DNS:<host>,IP:<ip_host>" 
```
**Note**: the Subject Alternative Name (SAN) specified above is important for browser hostname validation, make sure it is the same as the IP/DNS address you and your clients will access the server from.

4. Run server script
```bash
python server.py
```
4. Open the admin panel at `https://<host>:<port>/admin`(**NOT** `http://`, this uri will not connect to the server at all) in a browser. 

After this, you will be prompted for a username and password. Enter the admin credentials set in the `.env` file, and if successful you should enter the admin panel.

# Features
- Minimal dependencies(`aiohttp` and `python-dotenv`)
- Zero build step, just run the script
- Mobile-friendly adaptive interface
- Proper DB CRUD for the admin panel
- Doesn't necessarily need an internet connection due to being P2P, can work over local networks
- Has push-to-talk and mute toggle modes for mute modes
- Adjustable and persistant audio profile settings for users
- Lightweight
- Simple, easy to audit and run on-premises

# Roadmap
- [] User role strings
- [] More admin tools(kick users, mute users)
- [] Dark mode
- [] WebRTC shim for server federation

# License
This repo is licensed under the MIT license.
See the [LICENSE](./LICENSE) file.