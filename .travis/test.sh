#!/bin/bash
if [ "$TRAVIS_OS_NAME" = "linux" ]
then
  # Linux
  UT_FLAGS=" -K tshark" # TODO: also test as root ?
  if [ "$TRAVIS_SUDO" != "true" ]
  then
    # Linux non root
    UT_FLAGS+=" -K manufdb"
  fi
  # pypy
  if python --version 2>&1 | grep -q PyPy
  then
    UT_FLAGS+=" -K not_pypy"
  fi
elif [ "$TRAVIS_OS_NAME" = "osx" ]
then
  # Travis CI in macOS 10.13+ can't load kexts. Need this for tuntaposx.
  UT_FLAGS=" -K tun -K tap"
fi

if [[ $TOXENV == py3* ]]
then
  # Some Python 3 tests currently fail. They should be tracked and
  # fixed.
  UT_FLAGS+=" -K FIXME_py3"
fi

if [[ ${TRAVIS_DIST:=trusty} == xenial ]]
then
  # The vcan module is currently unavailable on Travis-CI xenial builds
  UT_FLAGS+=" -K vcan_socket"
fi

# Dump UT_FLAGS (the others were already dumped in install.sh)
echo UT_FLAGS=$UT_FLAGS

tox -- $UT_FLAGS
