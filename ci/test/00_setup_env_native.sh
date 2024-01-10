#!/usr/bin/env bash
#
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export CONTAINER_NAME=ci_native
export CI_IMAGE_NAME_TAG="ubuntu:20.04"
# Use minimum supported python3.8 and gcc-8 (or best-effort gcc-9), see doc/dependencies.md
export PACKAGES="gcc-9 g++-9 python3-zmq libdbus-1-dev libharfbuzz-dev"
export DEP_OPTS="NO_UPNP=1 NO_NATPMP=1 DEBUG=1 ALLOW_HOST_PACKAGES=1 CC=gcc-9 CXX=g++-9"
export TEST_RUNNER_EXTRA="--previous-releases --coverage --extended --exclude feature_dbcrash"  # Run extended tests so that coverage does not fail, but exclude the very slow dbcrash
export RUN_UNIT_TESTS_SEQUENTIAL="true"
export RUN_UNIT_TESTS="false"
export GOAL="install"
export NO_WERROR=1
export DOWNLOAD_PREVIOUS_RELEASES="true"
export BITCOIN_CONFIG="--enable-zmq --with-libs=no --enable-reduce-exports \
--enable-debug CFLAGS=\"-g0 -O2 -funsigned-char\" CXXFLAGS=\"-g0 -O2 -funsigned-char\""