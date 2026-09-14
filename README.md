# Secure-Vault-Based-Mutual-Authentication-for-Constrained-IoT-Devices
SECURE VAULT MUTUAL AUTHENTICATION
COMPLETE LINUX VIRTUAL MACHINE SETUP AND DEMONSTRATION GUIDE

======================================================================
1. PROJECT CONTENTS
======================================================================

The project folder must have this structure:

SecureVaultProject/
|-- app.py
|-- schema.sql
|-- iot_auth.db
|-- iot_auth.sqbpro
|-- esp_client.ino
|-- replay.py
|-- dos.py
|-- firewall_rules_secure_vault.sh
`-- templates/
    `-- dashboard.html

The most important files are:

app.py
    Flask backend implementing the M1-M4 protocol, the dashboard API,
    authentication sessions, encrypted sensor-data reception, logging,
    rate limiting, and administrative access control.

iot_auth.db
    Initialized SQLite database containing the registered device
    ESP8266-01 and its initial secure vault.

schema.sql
    SQL schema used to recreate the database tables when required.

templates/dashboard.html
    Protected web dashboard showing the device status, M1-M4 timeline,
    vault status, application data, and technical logs.

esp_client.ino
    ESP8266/ESP32 Arduino client implementing the device side of the
    authentication protocol.

replay.py
    Functional security test that completes a valid authentication,
    sends one protected payload, and resends the same ciphertext to verify
    that the server rejects the replay.

dos.py
    Authorized laboratory load test that sends concurrent requests to the
    authentication endpoint.

firewall_rules_secure_vault.sh
    Ordered iptables policy for TCP port 5050.

======================================================================
2. CREATE THE UBUNTU VIRTUAL MACHINE
======================================================================

Step 1 - Install VirtualBox on the physical computer
----------------------------------------------------

Step 2 - Download Ubuntu
------------------------

Step 3 - Create the virtual machine
-----------------------------------

Step 4 - Log in to Ubuntu
-------------------------

======================================================================
3. COPY THE PROJECT INTO THE VIRTUAL MACHINE
======================================================================

The easiest methods are:

1. Copy the project from a USB drive.
2. Enable VirtualBox drag-and-drop after installing Guest Additions.
3. Use a VirtualBox shared folder.
4. Download a project ZIP inside Ubuntu and extract it.

For this guide, place the final folder in the Ubuntu user's Home directory:

    /home/<ubuntu-user>/SecureVaultProject

To confirm that the folder exists:

1. Open Terminal with Ctrl + Alt + T.
2. Run:

    cd ~/SecureVaultProject
    pwd
    ls

The ls command should display app.py, iot_auth.db, replay.py, dos.py,
firewall_rules_secure_vault.sh, and the templates directory.

Confirm that the dashboard is inside the templates directory:

    ls templates

Expected result:

    dashboard.html

Do not open dashboard.html by double-clicking it. The Flask server must serve
this file because its JavaScript communicates with protected backend routes.

======================================================================
4. INSTALL ALL LINUX AND PYTHON DEPENDENCIES
======================================================================

Step 5 - Update Ubuntu
----------------------
In Terminal, run:

    sudo apt update
    sudo apt upgrade -y

Ubuntu will ask for the password of the current Linux user. While typing the
password, no characters are shown; this is normal. Press Enter when finished.

Step 6 - Install the required system packages
---------------------------------------------
Run:

    sudo apt install -y python3 python3-pip python3-venv python3-dev \
        build-essential sqlite3 curl wget git nano iptables \
        iptables-persistent netfilter-persistent

If the iptables-persistent installer asks whether the current IPv4 or IPv6 rules
should be saved, either answer is acceptable at this stage. The final project
rules will be saved later after they are applied.

Step 7 - Enter the project directory
------------------------------------

    cd ~/SecureVaultProject

Step 8 - Create a Python virtual environment
--------------------------------------------

    python3 -m venv .venv

Step 9 - Activate the virtual environment
-----------------------------------------

    source .venv/bin/activate

The Terminal prompt should now begin with:

    (.venv)

The virtual environment must be activated again whenever a new Terminal window
is opened.

Step 10 - Install every required Python library
-----------------------------------------------

    python -m pip install --upgrade pip setuptools wheel
    python -m pip install Flask pycryptodome requests

The libraries are used as follows:

    Flask          web server, sessions, protected dashboard, and REST routes
    pycryptodome   AES-CBC encryption used by app.py and replay.py
    requests       HTTP client used by replay.py and dos.py

Verify the installation:

    python -c "import flask, requests; from Crypto.Cipher import AES; print('Python dependencies installed correctly')"

Expected output:

    Python dependencies installed correctly

======================================================================
5. VERIFY AND BACK UP THE DATABASE
======================================================================

Step 11 - Check the supplied SQLite database
--------------------------------------------
From the project directory, run:

    sqlite3 iot_auth.db "PRAGMA integrity_check;"

Expected output:

    ok

Confirm that the registered device exists:

    sqlite3 iot_auth.db "SELECT device_id, vault_version, n_keys, key_size_bytes FROM devices;"

Expected device identifier:

    ESP8266-01

Step 12 - Create a clean demonstration backup
---------------------------------------------
The secure vault changes after every successful authentication. Keep an original
copy of the initialized database so that demonstrations can always begin from the
same synchronized state:

    cp iot_auth.db iot_auth_initial_backup.db

To restore the initial demonstration state later, first stop the Flask server and
run:

    cp iot_auth_initial_backup.db iot_auth.db

The supplied database is the recommended starting point. If the database must be
created from schema.sql, use:

    rm -f iot_auth.db
    sqlite3 iot_auth.db < schema.sql
    sqlite3 iot_auth.db "INSERT INTO devices(device_id,vault,vault_version,n_keys,key_size_bytes,device_online,polling_interval_seconds,pending_command,created_at,updated_at) VALUES('ESP8266-01',X'D6F9A56E22F7C84613533526',1,12,1,0,5,0,datetime('now'),datetime('now'));"

Then create the backup again:

    cp iot_auth.db iot_auth_initial_backup.db

======================================================================
6. ADMINISTRATOR LOGIN CREDENTIALS
======================================================================

The application contains these demonstration credentials:

    Username: admin
    Password: demo123

The login page is protected by a Flask session. The values can also be overridden
with environment variables before starting the server:

    export ADMIN_USERNAME="admin"
    export ADMIN_PASSWORD="demo123"
    export FLASK_SECRET_KEY="secure-vault-laboratory-secret"

For the submitted demonstration, the username and password to enter are:

    admin
    demo123

======================================================================
7. START THE FLASK SERVER
======================================================================

Step 13 - Start the backend
---------------------------
Make sure the virtual environment is active and run:

    cd ~/SecureVaultProject
    source .venv/bin/activate
    python app.py

Expected Terminal output includes:

    Running on http://127.0.0.1:5050
    Running on http://<VM-IP>:5050

Leave this Terminal window open. It displays the HTTP requests received by the
server and the protocol execution activity.

Step 14 - Open the dashboard inside Ubuntu
------------------------------------------
Open Firefox inside the Ubuntu virtual machine and visit:

    http://127.0.0.1:5050

The browser is redirected to the Administrator Access page.

Enter:

    Username: admin
    Password: demo123

After login, the dashboard displays:

    - server and device connectivity;
    - current session and vault status;
    - M1, M2, M3, and M4 progress;
    - synchronized vault-update progress;
    - application telemetry;
    - technical and security logs.

Step 15 - Stop the server when required
---------------------------------------
Return to the Terminal running app.py and press:

    Ctrl + C

======================================================================
8. OPTIONAL: OPEN THE DASHBOARD FROM THE HOST COMPUTER
======================================================================

The simplest demonstration uses Firefox inside the Ubuntu VM. To access the
server from the physical host computer, use one of the following configurations.

Method A - VirtualBox NAT port forwarding
-----------------------------------------
1. Shut down the VM.
2. In VirtualBox, open Settings -> Network -> Adapter 1.
3. Select NAT.
4. Open Advanced -> Port Forwarding.
5. Add this rule:

    Name: SecureVault
    Protocol: TCP
    Host IP: 127.0.0.1
    Host Port: 5050
    Guest IP: leave empty
    Guest Port: 5050

6. Start the VM and run python app.py.
7. On the physical host, open:

    http://127.0.0.1:5050

Method B - Bridged Adapter
--------------------------
1. Shut down the VM.
2. Open Settings -> Network -> Adapter 1.
3. Select Bridged Adapter and choose the active Wi-Fi or Ethernet interface.
4. Start Ubuntu.
5. Find the VM address:

    hostname -I

6. From another device on the same authorized network, open:

    http://<VM-IP>:5050

======================================================================
9. RUN THE SOFTWARE-ONLY AUTHENTICATION AND REPLAY DEMONSTRATION
======================================================================

This is the fastest complete test because replay.py behaves as an authorized IoT
client and performs the complete M1-M4 exchange without requiring a physical
board.

Step 16 - Restore the initialized vault before the test
-------------------------------------------------------
Stop the Flask server with Ctrl + C, then run:

    cd ~/SecureVaultProject
    cp iot_auth_initial_backup.db iot_auth.db

Step 17 - Configure the local authorized target
-----------------------------------------------
The VM-local server address is:

    http://127.0.0.1:5050

Configure both test scripts for the local VM with:

    sed -i 's|http://188.218.211.175:5050|http://127.0.0.1:5050|g' replay.py dos.py

Step 18 - Restart the server
----------------------------
In Terminal 1:

    cd ~/SecureVaultProject
    source .venv/bin/activate
    python app.py

Step 19 - Open a second Terminal
--------------------------------
Press Ctrl + Alt + T and run:

    cd ~/SecureVaultProject
    source .venv/bin/activate
    python replay.py

Expected sequence:

    1. /auth/start returns HTTP 200 and M2.
    2. /auth/respond returns HTTP 200 and M4.
    3. The client derives the session key.
    4. The first /session/data request returns HTTP 200.
    5. The identical ciphertext is sent again.
    6. The replayed request returns HTTP 409.

The expected final message is equivalent to:

    first send accepted
    second identical send rejected as replay / invalid counter

Keep the dashboard open during the test to observe the M1-M4 timeline, session
status, vault update, sensor values, and logs.

======================================================================
10. VERIFY ADMINISTRATIVE ACCESS CONTROL
======================================================================

Open a new Terminal while the Flask server is running and execute:

    curl -i http://127.0.0.1:5050/ui/dashboard

Because curl has no authenticated browser session, the expected response is:

    HTTP/1.1 401 UNAUTHORIZED

The protected dashboard becomes available only after logging in with:

    Username: admin
    Password: demo123

To verify invalid login handling, open a new private browser window and enter an
incorrect password. The dashboard must remain inaccessible.

======================================================================
11. VERIFY MALFORMED-CIPHERTEXT REJECTION
======================================================================

This test opens an authentication context and then sends an invalid encrypted M3
message. Run the following commands from a second Terminal:

    SESSION_ID="malformed-$(date +%s)"

    curl -s -X POST http://127.0.0.1:5050/auth/start \
        -H "Content-Type: application/json" \
        -d "{\"device_id\":\"ESP8266-01\",\"session_id\":\"$SESSION_ID\"}"

    curl -i -X POST http://127.0.0.1:5050/auth/respond \
        -H "Content-Type: application/json" \
        -d "{\"device_id\":\"ESP8266-01\",\"session_id\":\"$SESSION_ID\",\"ciphertext\":\"AAAA\"}"

The server must reject the invalid ciphertext and return a generic authentication
error rather than exposing an internal stack trace or database information. The
dashboard records the failed protocol state.

======================================================================
12. RUN THE AUTHORIZED REQUEST-FLOOD TEST
======================================================================

IMPORTANT: Run dos.py only against the local VM or another system for which
explicit authorization has been granted. Never point it at a third-party server.

The supplied experiment uses concurrent requests to /auth/start while checking
/health or server responsiveness. The submitted configuration contains:

    NUM_THREADS = 100
    DURATION_SECONDS = 60

For a short classroom demonstration, smaller values may be selected in dos.py,
for example 10 threads for 15 seconds. For the recorded project experiment, use
the supplied values inside an isolated laboratory VM.

Step 20 - Run the test before applying the host firewall
--------------------------------------------------------
Keep app.py running in Terminal 1. In Terminal 2, run:

    cd ~/SecureVaultProject
    source .venv/bin/activate
    python dos.py

Observe the request counter and server response time. The application-level rate
limits continue to reject excessive authentication attempts even though the
requests have already reached Flask.

======================================================================
13. APPLY THE COMPLETE IPTABLES FIREWALL POLICY
======================================================================

The firewall is designed for a Linux server and protects TCP port 5050 before
requests reach Flask. Use a fresh or recoverable virtual machine and apply the
policy from the local VM console.

Step 21 - Save the current firewall configuration
-------------------------------------------------

    sudo iptables-save | sudo tee ~/iptables_before_secure_vault.rules > /dev/null

Step 22 - Make the script executable
------------------------------------

    cd ~/SecureVaultProject
    chmod +x firewall_rules_secure_vault.sh

Step 23 - Apply the firewall
----------------------------

    sudo ./firewall_rules_secure_vault.sh

The script applies the following ordered policy:

    1. Default INPUT policy: DROP
    2. Default FORWARD policy: DROP
    3. Default OUTPUT policy: ACCEPT
    4. Accept loopback traffic
    5. Accept ESTABLISHED and RELATED traffic
    6. Accept SSH on TCP port 22
    7. Drop port-5050 traffic above 2 requests/second per source IP,
       after a burst of 10
    8. Drop connections above 10 simultaneous TCP connections per source
    9. Accept the remaining TCP traffic to port 5050

Step 24 - Display the active rules
----------------------------------

    sudo iptables -L INPUT -n -v --line-numbers

The output should show the loopback rule, established/related rule, SSH rule,
hashlimit rule, connlimit rule, and final port-5050 ACCEPT rule.

Step 25 - Save the active policy across VM restarts
--------------------------------------------------

    sudo netfilter-persistent save
    sudo netfilter-persistent reload

Step 26 - Confirm that the dashboard still works
------------------------------------------------
With app.py running, open:

    http://127.0.0.1:5050

Log in with:

    Username: admin
    Password: demo123

The legitimate dashboard and device traffic should remain available.

Step 27 - Repeat the authorized flood test
------------------------------------------
In Terminal 2:

    source ~/SecureVaultProject/.venv/bin/activate
    cd ~/SecureVaultProject
    python dos.py

Compare the request count and responsiveness with the previous run. The host
firewall rejects excessive traffic before Flask performs JSON parsing, database
access, or cryptographic processing.

Step 28 - Restore the previous firewall rules if necessary
----------------------------------------------------------
From the local VM console:

    sudo iptables-restore < ~/iptables_before_secure_vault.rules

To save the restored configuration:

    sudo netfilter-persistent save

======================================================================
14. RUN THE ESP8266 OR WOKWI CLIENT
======================================================================

The complete hardware-oriented demonstration uses esp_client.ino. The sketch
contains the registered identifier:

    ESP8266-01

and communicates with TCP port:

    5050

Step 29 - Install Arduino IDE on Ubuntu, when using a physical board
-------------------------------------------------------------------
Arduino IDE can be downloaded from the official Arduino website. After installing
it, open Boards Manager and install the ESP8266 board package. Select the correct
NodeMCU/ESP8266 board and serial port.

Step 30 - Install the Arduino libraries
---------------------------------------
From Arduino IDE -> Library Manager, install:

    ArduinoJson
    Crypto by Rhys Weatherley

The sketch also uses the Wi-Fi and HTTP libraries supplied by the selected
ESP8266 or ESP32 board package.

Step 31 - Configure Wi-Fi and server connectivity
-------------------------------------------------
For Wokwi, the sketch can use:

    WIFI_SSID = Wokwi-GUEST
    WIFI_PASS = "" #empty, there isn't a psw

For a physical board, enter the credentials of an authorized Wi-Fi network.

The SERVER_HOST value must be an address that the device can reach:

    - for a physical board on the same LAN, use the bridged Ubuntu VM address;
    - for Wokwi over the Internet, use an authorized public address or a
      controlled tunnel/port-forwarding configuration;
    - SERVER_PORT remains 5050.

Find the Ubuntu VM private address with:

    hostname -I

Step 32 - Start the complete demonstration
------------------------------------------
1. Restore the synchronized initial database if starting a clean run.
2. Start app.py.
3. Open and log in to the dashboard.
4. Start the ESP8266/Wokwi sketch.
5. Wait for the device heartbeat to appear.
6. Click "Launch demo" on the dashboard.
7. The device polls the server and receives the start command.
8. Observe M1, M2, M3, M4, session-key generation, and the vault update.
9. Observe the protected application payload and sensor history.

The dashboard should progress from Waiting/Pending to successful device and
server authentication, generated session key, updated vault, and received
application data.

======================================================================
15. TOTAL STEP 
======================================================================

For a clear presentation, use this order:

1. Start the Ubuntu VM.
2. Open Terminal.
3. Enter the project directory:

       cd ~/SecureVaultProject

4. Activate the Python environment:

       source .venv/bin/activate

5. Start the server:

       python app.py

6. Open Firefox at:

       http://127.0.0.1:5050

7. Log in with:

       Username: admin
       Password: demo123

8. Show the dashboard sections and the current idle state.
9. Run the ESP/Wokwi client or run replay.py as the software client.
10. Show the M1-M4 progress, generated session key, vault update, telemetry,
    and technical logs.
11. Demonstrate unauthenticated dashboard rejection with curl.
12. Demonstrate malformed-ciphertext rejection.
13. Demonstrate replay rejection with replay.py.
14. Display the firewall rules:

       sudo iptables -L INPUT -n -v --line-numbers

15. Run the authorized request-flood test in the VM and show the effect of the
    application controls and host firewall.
16. Stop the Flask server with Ctrl + C when finished.

======================================================================
16. COMMON PROBLEMS
======================================================================

Problem: "ModuleNotFoundError: No module named flask"
Solution:

    cd ~/SecureVaultProject
    source .venv/bin/activate
    python -m pip install Flask pycryptodome requests

Problem: "No module named Crypto"
Solution:

    source .venv/bin/activate
    python -m pip install --upgrade pycryptodome

Problem: dashboard.html is not found
Solution:
Verify this exact path:

    ~/SecureVaultProject/templates/dashboard.html

Problem: the browser cannot connect
Solution:
1. Confirm that python app.py is still running.
2. Confirm that the address is http://127.0.0.1:5050.
3. Check the listening port:

    ss -ltnp | grep 5050

Problem: the ESP device cannot reach the server
Solution:
1. Use Bridged Adapter networking for the VM.
2. Run hostname -I and configure that reachable address in the sketch.
3. Confirm that TCP port 5050 is allowed by the firewall.
4. Confirm that app.py is bound to 0.0.0.0:5050.

Problem: replay.py fails after a previous successful run
Solution:
The vault evolves after authentication. Stop the server, restore the synchronized
initial database, and restart:

    cp iot_auth_initial_backup.db iot_auth.db
    python app.py

Problem: the firewall blocks an expected connection
Solution:
Restore the saved rules from the VM console:

    sudo iptables-restore < ~/iptables_before_secure_vault.rules

END OF GUIDE
