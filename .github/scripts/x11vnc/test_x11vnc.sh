#!/bin/bash

# Usage: ./test_x11vnc.sh [log_file]
# If no log file is provided, defaults to "x11vnc_test.log"

# Set default log file
LOG_FILE="${1:-x11vnc_test.log}"

# Show usage if help is requested
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "Usage: $0 [log_file]"
    echo "  log_file: Path to the log file (default: x11vnc_test.log)"
    echo "  -h, --help: Show this help message"
    exit 0
fi

SCRIPTS_DIR="$GITHUB_WORKSPACE/.github/scripts/x11vnc"

killall x11vnc > /dev/null 2> /dev/null
killall Xvfb > /dev/null 2> /dev/null

X11VNC_TEST_FAIL=0


# CA / cert generation


echo -e "\n\nTesting -sslGenCA\n" > "$LOG_FILE"

$SCRIPTS_DIR/x11vnc_sslgenca.exp >> "$LOG_FILE" 2>> "$LOG_FILE"

if [ $? -eq 0 ] && [ -f "ca-dir/CA/cacert.pem" ] && [ -f "ca-dir/CA/private/cakey.pem" ]
then
    echo "[ PASSED ] -sslGenCA"
else
    echo "[ FAILED ] -sslGenCA"
    X11VNC_TEST_FAIL=1
fi


echo -e "\n\nTesting -sslGenCert client\n" >> "$LOG_FILE"

$SCRIPTS_DIR/x11vnc_sslgencert_client.exp >> "$LOG_FILE" 2>> "$LOG_FILE"

if [ $? -eq 0 ] && [ -f "ca-dir/clients/wolf.pem" ] && [ -f "ca-dir/clients/wolf.crt" ]
then
    echo "[ PASSED ] -sslGenCert client"
else
    echo "[ FAILED ] -sslGenCert client"
    X11VNC_TEST_FAIL=1
fi


echo -e "\n\nTesting -sslGenCert server\n" >> "$LOG_FILE"

$SCRIPTS_DIR/x11vnc_sslgencert_server.exp >> "$LOG_FILE" 2>> "$LOG_FILE"

if [ $? -eq 0 ] && [ -f "ca-dir/server-wolf.pem" ] && [ -f "ca-dir/server-wolf.crt" ]
then
    echo "[ PASSED ] -sslGenCert server"
else
    echo "[ FAILED ] -sslGenCert server"
    X11VNC_TEST_FAIL=1
fi


echo -e "\n\nTesting -sslCertInfo\n" >> "$LOG_FILE"

OPENSSL_CONF='' OPENSSL_MODULES='' timeout 5 x11vnc -sslCertInfo ca-dir/server-wolf.pem > cert_info_ossl.txt
timeout 5 x11vnc -sslCertInfo ca-dir/server-wolf.pem > cert_info.txt

if [ $? -eq 0 ] && diff -y cert_info.txt cert_info_ossl.txt >> "$LOG_FILE" 2>> "$LOG_FILE" \
    && cat cert_info.txt >> "$LOG_FILE"
then
    echo "[ PASSED ] -sslCertInfo"
else
    echo "[ FAILED ] -sslCertInfo"
    X11VNC_TEST_FAIL=1
fi


echo -e "\n\nTesting -sslEncKey\n" >> "$LOG_FILE"

$SCRIPTS_DIR/x11vnc_sslenckey.exp >> "$LOG_FILE" 2>> "$LOG_FILE"

if [ $? -eq 0 ] && grep -q "BEGIN ENCRYPTED PRIVATE KEY" ca-dir/server-wolf.pem
then
    echo "[ PASSED ] -sslEncKey"
else
    echo "[ FAILED ] -sslEncKey"
    X11VNC_TEST_FAIL=1
fi


# SSL


# Setup Xvfb, which is a purely virtual display, i.e., humans cannot see it
# but it works the same as any other X server
Xvfb :0 -screen 0 100x100x8 2>> "$LOG_FILE" &
sleep 2


# Testing with SSL will use the TLSNone security type
echo -e "\n\nTesting -ssl handshake, authentication, initialization...\n" >> "$LOG_FILE"

PORT=`x11vnc -ssl TMP -display :0 -localhost -bg -o server.log`
PORT=`echo "$PORT" | grep -m 1 "PORT=" | sed -e 's/PORT=//'`

timeout 15 vncviewer -GnuTLSPriority=LEGACY -DesktopSize=0 -display :0 -log *:stderr:100 localhost::$PORT 2> client.log

if grep -Eq "SSL: handshake with helper process[[0-9]+] succeeded" server.log \
    && grep -q "CConnection: Authentication success" client.log \
    && grep -q "CConnection: initialisation done" client.log
then
    echo "[ PASSED ] -ssl handshake, authentication, initialization"
else
    echo "[ FAILED ] -ssl handshake, authentication, initialization"
    X11VNC_TEST_FAIL=1
fi
killall x11vnc > /dev/null 2> /dev/null
cat server.log client.log >> "$LOG_FILE"


# Testing with a password changes the security type from TLSNone to TLSVnc
echo -e "\n\nTesting -ssl with a password...\n" >> "$LOG_FILE"

x11vnc -storepasswd wolfprov passwd 2>> "$LOG_FILE"

PORT=`x11vnc -ssl TMP -display :0 -localhost -bg -o server.log -rfbauth passwd`
PORT=`echo "$PORT" | grep -m 1 "PORT=" | sed -e 's/PORT=//'`

timeout 15 vncviewer -GnuTLSPriority=LEGACY -DesktopSize=0 -display :0 -passwd passwd -log *:stderr:100 localhost::$PORT 2> client.log

if grep -Eq "SSL: handshake with helper process[[0-9]+] succeeded" server.log \
    && grep -q "CConnection: Authentication success" client.log \
    && grep -q "CConnection: initialisation done" client.log
then
    echo "[ PASSED ] -ssl with a password"
else
    echo "[ FAILED ] -ssl with a password"
    X11VNC_TEST_FAIL=1
fi
killall x11vnc > /dev/null 2> /dev/null
cat server.log client.log >> "$LOG_FILE"


# HTTP HTTPS


echo "<html><body>Use WolfSSL!</body></html>" > index.html


PORT=`x11vnc -ssl TMP -display :0 -localhost -httpdir . -https 5678 -bg -o server.log`
PORT=`echo "$PORT" | grep -m 1 -Eo "http://localhost:[0-9]+" server.log | sed -e 's/http:\/\/localhost://'`

echo -e "\n\nTesting -https with http...\n" >> "$LOG_FILE"

if OPENSSL_CONF='' OPENSSL_MODULES='' curl -ks "http://localhost:$PORT/index.html" >> "$LOG_FILE"
then
    echo "[ PASSED ] -https with an http request"
else
    echo "[ FAILED ] -https with an http request"
    X11VNC_TEST_FAIL=1
fi


echo -e "\n\nTesting -https with https...\n" >> "$LOG_FILE"

if OPENSSL_CONF='' OPENSSL_MODULES='' curl -ks "https://localhost:5678/index.html" >> "$LOG_FILE"
then
    echo "[ PASSED ] -https with an https request"
else
    echo "[ FAILED ] -https with an https request"
    X11VNC_TEST_FAIL=1
fi

killall x11vnc > /dev/null 2> /dev/null || true
killall Xvfb > /dev/null 2> /dev/null || true
cat server.log >> "$LOG_FILE"

printf "\n\nX11VNC_TEST_FAIL: $X11VNC_TEST_FAIL\n\n"
exit $X11VNC_TEST_FAIL

