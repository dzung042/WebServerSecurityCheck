#!/bin/ksh
#set -x
#
##############################################################################
#
#	Author: 	    Fabio Zambrino <fabio@zambroid.ch>
#	Creation date:	May 21 2019
#	Description:	This check if a server is affected by known vulnerabilities
#
#
# ----------------------------------------------------------------------------
#   version     date            author      description
# ----------------------------------------------------------------------------
#   1.0.0       04.02.2019	    zambroid    Initial version
#
##############################################################################

#############
# VARIABLES #
#############
ZZ_TIME_STAMP=$(date '+%Y-%m-%d_%H%M%S')
ZZ_WSSC_DIR=$HOME/WSSC

#############
# FUNCTIONS #
#############

##############################################################################
# print message to stdout
##############################################################################

function print_msg {
  print "$(date '+[%d.%m.%Y %H:%M:%S]') $1 : $2"
}

##############################################################################
# print message to stderr
##############################################################################

function print_msg_stderr {
  print -u2 "$(date '+[%d.%m.%Y %H:%M:%S]') $1 : $2"
}

##############################################################################
# print message box
##############################################################################

function print_msg_box {
  print "##############################################################################"
  print "$(date '+[%d.%m.%Y %H:%M:%S]') $1"
  print "##############################################################################"
  print
}

##############################################################################
# log command
##############################################################################

function log_script {
  print_msg "INFO" "Script started"
  exec 3>&1 4>&2 1>> $1 2>&1
  print_msg "INFO" "Script started"
 }

##############################################################################
# log command verbose
##############################################################################

function log_script_verbose {
  print_msg "INFO" "Script started"
  exec 3>&1 4>&2 1>> $1 2>&1
  print_msg "INFO" "Script started"
  set -v
 }

##############################################################################
# stop logging
##############################################################################

function stop_log {
  set +v
  print_msg_box "Script ended"
  exec 1>&3 2>&4 3>&- 4>&-
  print_msg "Logging stopped"
 }

##############################################################################
# function get command line arguments
##############################################################################

function get_args {
  while [[ $# -gt 0 ]]; do
    case $1 in
      # HOST
      -host)
        shift
        if [[ -n $1 ]]; then
          ZZ_SSL_HOST=$1
          shift
        fi
        ;;
      # DISPLAY FROM
      -port)
        shift
        if [[ -n $1 ]]; then
          ZZ_SSL_PORT=$1
          shift
        fi
        ;;
      -h)
        usage_message
        ;;
      *)
        usage_message "Invalid argument found"
        ;;

    esac
  done

  if [[ -z $ZZ_SSL_HOST || -z $ZZ_SSL_HOST ]]; then
    usage_message "Missing parameter"
  fi

}

##############################################################################
# USAGE MESSAGE
##############################################################################

function usage_message {

  # error message is passed as argument

  if [[ -n "$1" ]]; then
    print
    print "Command : wssc.sh $ZZ_ARGS"
    print
    print "Error   : $1"
  fi

  # display usage

  print
  print "Purpose : Verify WebServer Security"
  print
  print "Usage   : wssc.sh -host <DNS_ALIAS> -port <HTTPS_PORT>"
  print "          -host put the dns alias of the host to be scanned"
  print "          -port put the SSL port to test"
  print "          -h display usage help"
  print
  print "Example : wssc.sh -host gonsbox2.mstr.ubsdev.net -port 443"
  print
  print

  exit 1

}

##############################################################################
# function to test that only TLSv1.2 is enabled
##############################################################################
function zz_test_ssl_versions {
  for zz_protocol in ssl2 ssl3 tls1 tls1_1 tls1_2
  do
    ZZ_CIPHER=$(echo '' | openssl s_client -connect $ZZ_SSL_HOST:$ZZ_SSL_PORT -$zz_protocol 2>/dev/null | perl -ne "print $a /.*Cipher\s+: (.*)/")
    if [[ $ZZ_CIPHER == "0000" ]]; then
      print_msg "INFO" "$zz_protocol is disabled"
    else
      print_msg "INFO" "$zz_protocol enabled"
    fi

  done
}

##############################################################################
# function to test signature algorithm
##############################################################################
function zz_test_signature_algorithm {
  ZZ_SIGN_ALG=$(echo '' | openssl s_client -connect $ZZ_SSL_HOST:$ZZ_SSL_PORT -servername $ZZ_SSL_HOST 2>/dev/null | openssl x509 -noout -text | grep -m1 'Signature Algorithm' | perl -ne "print $a /.*Signature Algorithm: (.*)/")
  if [[ $ZZ_SIGN_ALG == "sha512WithRSAEncryption" ]]; then
    print_msg "INFO" "Certificate signed with SHA2: $ZZ_SIGN_ALG"
  else
    print_msg "WARN" "Certificate signed with weak algorithm: $ZZ_SIGN_ALG"
  fi
}

##############################################################################
# function to test enabled ciphers
##############################################################################
function zz_test_enabled_ciphers {
  ZZ_CIPHERS=$(openssl ciphers 'ALL:eNULL' | sed -e 's/:/ /g')
  print "Obtaining cipher list from $(openssl version)."

  for cipher in ${ZZ_CIPHERS[@]}
  do
    ZZ_RESULT=$(echo -n | openssl s_client -cipher "$cipher" -connect $ZZ_SSL_HOST:$ZZ_SSL_PORT 2>&1)
    if [[ "$ZZ_RESULT" =~ ":error:" ]] ; then
      ZZ_ERROR=$(echo -n $ZZ_RESULT | cut -d':' -f6)
    else
      if [[ "$ZZ_RESULT" =~ "Cipher is ${cipher}" || "$ZZ_RESULT" =~ "Cipher    :" ]] ; then
        print_msg "INFO" "Cipher $cipher is enabled"
      else
        echo UNKNOWN RESPONSE
        echo $ZZ_RESULT
      fi
    fi
  done
}

##############################################################################
# function to verify issuer
##############################################################################
function zz_verify_issuer {
  ZZ_ISSUER=$(echo '' | openssl s_client -connect $ZZ_SSL_HOST:$ZZ_SSL_PORT -servername $ZZ_SSL_HOST 2>/dev/null | openssl x509 -noout -text | perl -ne "print $a /Issuer:.*CN=(.*)/")
  print_msg "INFO" "Certificate issued by $ZZ_ISSUER"
}

##############################################################################
# function to verify CommonName
##############################################################################
function zz_verify_cn {
  ZZ_COMMON_NAME=$(echo '' | openssl s_client -connect $ZZ_SSL_HOST:$ZZ_SSL_PORT -servername $ZZ_SSL_HOST 2>/dev/null | openssl x509 -noout -text | perl -ne "print $a /Subject:.*CN=(.*)/")
  if [[ $ZZ_COMMON_NAME == $ZZ_SSL_HOST ]]; then
    print_msg "INFO" "Certificate correctly signed for $ZZ_COMMON_NAME"
  else
    print_msg "ERROR" "Certificate signed with different alias than the specified"
  fi
}

##############################################################################
# function to verify compression
##############################################################################
function zz_verify_compression {
  ZZ_COMPRESSION=$(echo '' | openssl s_client -connect $ZZ_SSL_HOST:$ZZ_SSL_PORT -servername $ZZ_SSL_HOST 2>/dev/null | perl -ne "print $a /Compression: (.*)/")
  if [[ $ZZ_COMPRESSION == "NONE" ]]; then
    print_msg "INFO" "No compression enabled"
  else
    print_msg "WARN" "Compression $ZZ_COMPRESSION enabled"
  fi
}

##############################################################################
# function to verify mod_ssl version
##############################################################################
function zz_modssl_version {
  ZZ_MODSSL_PATH=$(locate mod_ssl.so)
  ZZ_MODSSL_VERSION=$(strings $ZZ_MODSSL_PATH | egrep -m1 '^OpenSSL [0-9]')
  print_msg "INFO" "MOD_SSL Version is $ZZ_MODSSL_VERSION"
}

##############################################################################
# main
##############################################################################
get_args "$@"

ZZ_WORKING_DIR=$ZZ_WSSC_DIR/$ZZ_SSL_HOST
ZZ_WSSC_LOG=$ZZ_WORKING_DIR/wat_${ZZ_TIME_STAMP}.log
mkdir -p $ZZ_WORKING_DIR

print_msg "INFO" "Log will be saved in ${ZZ_WSSC_LOG}"
# start logging
log_script_verbose $ZZ_WSSC_LOG

print_msg_box "$ZZ_SSL_HOST"

zz_verify_compression
zz_verify_cn
zz_verify_issuer
zz_test_enabled_ciphers
zz_test_signature_algorithm
zz_test_ssl_versions
zz_modssl_version

# stop logging
stop_log

print_msg "INFO" "Script ended"

exit 0
