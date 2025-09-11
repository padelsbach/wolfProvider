#!/bin/bash
# install-packages.sh
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# This file is part of wolfProvider.
#
# wolfProvider is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfProvider is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.

# This script is used to install the wolfSSL, OpenSSL, and wolfProvider packages.
# It tries to find the packages and install all 3. It checks that wolfProvider is 
# installed and enabled as the default provider.

set -e

APT_INSTALL_CMD="apt install --reinstall -y "
REPO_ROOT=${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}

# Function to show usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --wolfssl-dir DIR     Directory containing wolfSSL .deb packages"
    echo "  --openssl-dir DIR     Directory containing OpenSSL .deb packages"
    echo "  --wolfprov-dir DIR    Directory containing wolfProvider .deb packages"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --wolfssl-dir /custom/wolfssl --openssl-dir /custom/openssl --wolfprov-dir /custom/wolfprov"
}

# Function to install wolfSSL packages
install_wolfssl() {
    local wolfssl_dir="$1"
    
    if [ -n "$wolfssl_dir" ]; then
        wolfssl_debs=$(ls -1 "$wolfssl_dir"/*.deb 2>/dev/null || true)
        printf "wolfssl_debs: $wolfssl_debs\n"
        if [ -z "$wolfssl_debs" ]; then
            echo "No wolfSSL .deb packages found in $wolfssl_dir"
            return 1
        fi
        echo "Installing wolfSSL: $wolfssl_debs"
        $APT_INSTALL_CMD $wolfssl_debs
        return $?
    else
        # wolfSSL must be already installed. Check that it is installed.
        if ! dpkg -l | grep -q "^ii.*libwolfssl "; then
            echo "libwolfssl package not found and path was not specified"
            return 1
        fi
        if ! dpkg -l | grep -q "^ii.*libwolfssl-dev "; then
            echo "libwolfssl-dev package not found and path was not specified"
            return 1
        fi
        printf "wolfSSL already installed\n"
        return 0
    fi
}

# Function to install OpenSSL packages
install_openssl() {
    local openssl_dir="$1"
    
    if [ -n "$openssl_dir" ]; then
        openssl_debs=$(ls -1 "$openssl_dir"/openssl_[0-9]*.deb 2>/dev/null || true)
        libssl3_debs=$(ls -1 "$openssl_dir"/libssl3_[0-9]*.deb 2>/dev/null || true)
        libssl_dev_debs=$(ls -1 "$openssl_dir"/libssl-dev_[0-9]*.deb 2>/dev/null || true)

        printf "openssl_debs: $openssl_debs\n"
        printf "libssl3_debs: $libssl3_debs\n"
        printf "libssl_dev_debs: $libssl_dev_debs\n"

        # Check that all required packages were found
        if [ -z "$openssl_debs" ]; then
            echo "No OpenSSL .deb packages found in $openssl_dir"
            return 1
        fi

        if [ -z "$libssl3_debs" ]; then
            echo "No libssl3 .deb packages found in $openssl_dir"
            return 1
        fi

        if [ -z "$libssl_dev_debs" ]; then
            echo "No libssl-dev .deb packages found in $openssl_dir"
            return 1
        fi

        # Install in dependency order: libssl3 first, then openssl, then dev headers
        if [ -n "$libssl3_debs" ]; then
            echo "Installing libssl3: $libssl3_debs"
            $APT_INSTALL_CMD $libssl3_debs || return 1
        fi
        if [ -n "$openssl_debs" ]; then
            echo "Installing openssl: $openssl_debs"
            $APT_INSTALL_CMD $openssl_debs || return 1
        fi
        if [ -n "$libssl_dev_debs" ]; then
            echo "Installing libssl-dev: $libssl_dev_debs"
            $APT_INSTALL_CMD $libssl_dev_debs || return 1
        fi
        return 0
    else
        # OpenSSL must be already installed. Check that it is installed.
        if ! dpkg -l | grep -q "^ii.*openssl "; then
            echo "openssl package not found and path was not specified"
            return 1
        fi
        printf "OpenSSL already installed\n"
        return 0
    fi
}

# Function to install wolfProvider packages
install_wolfprov() {
    local wolfprov_dir="$1"
    
    if [ -n "$wolfprov_dir" ]; then
        wolfprov_debs=$(ls -1 "$wolfprov_dir"/libwolfprov_[0-9]*.deb 2>/dev/null || true)
        printf "wolfprov_debs: $wolfprov_debs\n"

        # Check that all required packages were found
        if [ -z "$wolfprov_debs" ]; then
            echo "No libwolfprov .deb packages found in $wolfprov_dir"
            return 1
        fi

        echo "Installing wolfProvider main package: $wolfprov_debs"
        $APT_INSTALL_CMD $wolfprov_debs
        return $?
    else
        # wolfProvider must be already installed. Check that it is installed.
        if ! dpkg -l | grep -q "^ii.*libwolfprov"; then
            echo "libwolfprov package not found and path was not specified"
            return 1
        fi
        printf "wolfProvider already installed\n"
        return 0
    fi
}

# Parse command line arguments
UNKNOWN_OPTS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --wolfssl-dir)
            WOLFSSL_DIR="$2"
            shift 2
            ;;
        --openssl-dir)
            OPENSSL_DIR="$2"
            shift 2
            ;;
        --wolfprov-dir)
            WOLFPROV_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            # Collect unknown options instead of erroring out
            UNKNOWN_OPTS+=("$1")
            shift
            ;;
    esac
done

# Install wolfSSL first (only if directory was specified)
if ! install_wolfssl "$WOLFSSL_DIR"; then
    # Use local tarball of wolfSSL
    # TODO: build it from wolfSSL repo and remove tarball from repo
    WOLFSSL_TARBALL=${REPO_ROOT}/.github/packages/debian-wolfssl.tar.gz
    if ! ${REPO_ROOT}/debian/install-wolfssl.sh "$WOLFSSL_TARBALL" "$REPO_ROOT/.."; then
        printf "ERROR: Failed to build and install wolfSSL packages\n"
        exit 1
    fi
    if [ -n "$WOLFSSL_DIR" ]; then
      # Upon successful install, move the packages to the specified directory
      mkdir -p $WOLFSSL_DIR
      mv $REPO_ROOT/../*wolfssl*.deb $WOLFSSL_DIR
    fi
fi

# Install OpenSSL packages (only if directory was specified)
if ! install_openssl "$OPENSSL_DIR"; then
    printf "Trying to install from repo root: $REPO_ROOT/..\n"
    printf "Contents of $REPO_ROOT/..: $(ls -la $REPO_ROOT/..)\n"
    # Check the repo parent directory in case we just built the packages
    if ! install_openssl "$REPO_ROOT/.."; then
      printf "Trying to build and install OpenSSL packages\n"
      # Try building the missing packages
      yes "Y" | OPENSSL_TAG=$OPENSSL_TAG ${REPO_ROOT}/scripts/build-wolfprovider.sh --debian "${UNKNOWN_OPTS[@]}"
      if ! install_openssl "$REPO_ROOT/.."; then
        printf "ERROR: Failed to build and install OpenSSL packages\n"
        exit 1
      fi
    fi
    # Upon successful install, move the packages to the specified directory
    if [ -n "$OPENSSL_DIR" ]; then
      mkdir -p $OPENSSL_DIR
      mv $REPO_ROOT/../*ssl*.deb $OPENSSL_DIR
    fi
fi

# Install wolfProvider main package (only if directory was specified)
if ! install_wolfprov "$WOLFPROV_DIR"; then
    # Check the repo parent directory in case we just built the packages
    if ! install_wolfprov "$REPO_ROOT/.."; then
      # Try building the missing packages
      yes "Y" | ${REPO_ROOT}/scripts/build-wolfprovider.sh --debian "${UNKNOWN_OPTS[@]}"
      if ! install_wolfprov "$REPO_ROOT/.."; then
        printf "ERROR: Failed to build and install wolfProvider packages\n"
        exit 1
      fi
    fi

    # Upon successful install, move the packages to the specified directory
    if [ -n "$WOLFPROV_DIR" ]; then
      mkdir -p $WOLFPROV_DIR
      mv $REPO_ROOT/../*wolfprov*.deb $WOLFPROV_DIR
    fi
fi

# Check that wolfProvider is already loaded as the default provider
echo "Current OpenSSL providers:"
openssl list -providers
openssl list -providers | grep -q "wolfSSL Provider" || (echo "ERROR: libwolfprov not found in OpenSSL providers" && exit 1)

