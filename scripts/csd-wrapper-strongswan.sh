#!/bin/bash
# This file is modified version of OpenConnect CSD wrappers

if ! xmlstarlet --version > /dev/null 2>&1; then
    echo "************************************************************************" >&2
    echo "WARNING: xmlstarlet not found in path; CSD token extraction may not work" >&2
    echo "************************************************************************" >&2
    unset XMLSTARLET
else
    XMLSTARLET=true
fi

export RESPONSE=$(mktemp /tmp/csdresponseXXXXXXX)
export RESULT=$(mktemp /tmp/csdresultXXXXXXX)
export CERTANDKEY="client.pem"
export CACERT="ca.crt"
trap 'rm $RESPONSE $RESULT' EXIT

cat >> $RESPONSE <<EOF
endpoint.os.version="Windows 10";
endpoint.os.architecture="x64";
endpoint.os.processor_level="unknown";
endpoint.device.protection="none";
endpoint.device.protection_version="4.9.01095";
endpoint.device.hostname="MyPC1";
endpoint.device.port["135"]="true";
endpoint.device.port["445"]="true";
endpoint.device.port["5357"]="true";
endpoint.device.port["6006"]="true";
endpoint.device.tcp4port["135"]="true";
endpoint.device.tcp4port["445"]="true";
endpoint.device.tcp4port["5357"]="true";
endpoint.device.tcp4port["6006"]="true";
endpoint.device.udp4port["123"]="true";
endpoint.device.udp4port["500"]="true";
endpoint.device.udp4port["3702"]="true";
endpoint.device.tcp6port["135"]="true";
endpoint.device.tcp6port["445"]="true";
endpoint.device.tcp6port["5357"]="true";
endpoint.device.tcp6port["6006"]="true";
endpoint.device.udp6port["123"]="true";
endpoint.device.udp6port["500"]="true";
endpoint.device.udp6port["3702"]="true";
endpoint.device.MAC["8200.11aa.bbcc"]="true";
endpoint.certificate.user["0"]={};
endpoint.certificate.user["0"].subject_fulldn="CN=MyPC1.mydomain.com";
endpoint.certificate.user["0"].subject_cn="MyPC1.mydomain.com";
endpoint.certificate.user["0"].subject_store="capi_machine";
endpoint.certificate.user["0"].issuer_fulldn="CN=Some Root CA";
endpoint.certificate.user["0"].issuer_cn="Some Root CA";
endpoint.certificate.user["0"].issuer_ou="OrgUnit1";
endpoint.certificate.user["0"].issuer_o="MyOrg";
endpoint.certificate.user["0"].issuer_c="XX";
endpoint.certificate.user["0"].version="V3";
endpoint.certificate.user["0"].serial="ab:13:de:13:01:14:a4:77:13:ae";
endpoint.certificate.user["0"].time_valid_from="1622429353";
endpoint.certificate.user["0"].time_valid_to="1685561853";
endpoint.certificate.user["0"].sha1_hash="effc34fde0327fe9734a1599bcef087c12def341";
endpoint.device.id="WN49ZH17V1";
endpoint.os.hotfix["KB4577586"]="true";
endpoint.os.hotfix["KB4601556"]="true";
endpoint.os.hotfix["KB5004748"]="true";
EOF

TICKET=
STUB=0
CSD_HOSTNAME=
COOKIE_HEADER=

call_curl() {
    URL="$2"
    PINNEDPUBKEY="-k --cert $CERTANDKEY --cacert $CACERT"
    CACHECONTROL="Cache-Control: no-cache"
    CONNECTION="Connection: Close"
    PRAGMA="Pragma: no-cache"
    ACCEPTENCODING="Accept-Encoding: peerdist"
    if [ $1 -eq 2 ] || [ $1 -eq 3 ] || [ $1 -eq 5 ] || [ $1 -eq 6 ]; then
        ACCEPTENCODING="Accept-Encoding: identity"
    fi
    XTRANSCENTVERSION="X-Transcend-Version: 1"
    XANYCONNECTSTRAPPUBKEY="X-AnyConnect-STRAP-Pubkey: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExy2jK6gxcD3/M3l98tya3DSeyQCZq9HGeQxb2dHII8Meisg+fQj8xyEwgKJ/bYFPvwiFmEuXJLUf/KWR6tFPmg=="
    XP2PPPERDIST="X-P2P-PeerDist: Version=1.1"
    XP2PPPERDISTEX="X-P2P-PeerDistEx: MinContentInformation=1.0, MaxContentInformation=2.0"
    USERAGENT="User-Agent: AnyConnect Windows 4.9.01095"
    if [ $1 -eq 2 ] || [ $1 -eq 3 ] || [ $1 -eq 5 ] || [ $1 -eq 6 ]; then
        USERAGENT="User-Agent:"
    fi
    SDESKTOP="Cookie: sdesktop=$3"
    if [ $1 -eq 4 ]; then
        SDESKTOP="Cookie: sdesktop=$3; sdesktop=$3;"
    fi
    CONTENTTYPE="Content-Type: text/xml"
    ACCEPT="Accept:"
    XAGGREGATEAUTH="X-Aggregate-Auth: 1"
    case "$1" in
        1)
             curl $PINNEDPUBKEY \
             -H "$CACHECONTROL" \
             -H "$CONNECTION" \
             -H "$PRAGMA" \
             -H "$ACCEPTENCODING" \
             -H "$XTRANSCENTVERSION" \
             -H "$XANYCONNECTSTRAPPUBKEY" \
             -H "$XP2PPPERDIST" \
             -H "$XP2PPPERDISTEX" \
             -H "$USERAGENT" \
	     -H "$ACCEPT" \
             -s "$URL"
	     ;;
        2)
             curl $PINNEDPUBKEY \
             -H "$ACCEPTENCODING" \
             -H "$USERAGENT" \
             -s "$URL"
	     ;;
        3)
             curl $PINNEDPUBKEY \
             -H "$ACCEPTENCODING" \
	     -H "$SDESKTOP" \
             -H "$USERAGENT" \
             -s "$URL"
	     ;;
        4)
             curl $PINNEDPUBKEY \
             -H "$CACHECONTROL" \
             -H "$CONNECTION" \
             -H "$PRAGMA" \
             -H "$ACCEPTENCODING" \
	     -H "$SDESKTOP" \
             -H "$USERAGENT" \
             -H "$XTRANSCENTVERSION" \
             -H "$XTRANSCENTVERSION" \
	     -H "$XAGGREGATEAUTH" \
             -H "$XANYCONNECTSTRAPPUBKEY" \
             -H "$XP2PPPERDIST" \
             -H "$XP2PPPERDISTEX" \
	     -H "$ACCEPT" \
	     --write-out '%{http_code}' \
             -s "$URL"
	     ;;
        5)
             curl $PINNEDPUBKEY \
             -H "$ACCEPTENCODING" \
	     -H "$SDESKTOP" \
	     -H "$CONTENTTYPE" \
             -H "$USERAGENT" \
             -s "$URL" \
	     -H "Expect: " --data-binary @$4
	     ;;
        6)
             curl $PINNEDPUBKEY \
             -H "$ACCEPTENCODING" \
             -H "$USERAGENT" \
             -s -I "$URL"
	     ;;
     esac
}

while [ "$1" ]; do
    if [ "$1" == "-ticket" ];   then shift; TICKET=${1//\"/}; fi
    if [ "$1" == "-stub" ];     then shift; STUB=${1//\"/}; fi
    if [ "$1" == "-host" ];     then shift; CSD_HOSTNAME=${1//\"/}; fi
    shift
done

# based on real dump
URL="https://$CSD_HOSTNAME/CACHE/sdesktop/install/binaries/update.txt"
call_curl 1 $URL > /dev/null
URL="https://$CSD_HOSTNAME/CACHE/sdesktop/paths.txt"
call_curl 1 $URL > /dev/null
URL="https://$CSD_HOSTNAME/"
call_curl 6 $URL > /dev/null

URL="https://$CSD_HOSTNAME/+CSCOE+/sdesktop/token.xml?ticket=$TICKET&stub=$STUB"
if [ -n "$XMLSTARLET" ]; then
    TOKEN=$(call_curl 2 "$URL"  | xmlstarlet sel -t -v /hostscan/token)
else
    TOKEN=$(call_curl 2 "$URL" | sed -n '/<token>/s^.*<token>\(.*\)</token>^\1^p' )
fi

if [ -z "$TOKEN" ]; then
    echo "Unable to aquire TOKEN";
    exit 1
fi

# download manifest just to pretend
URL="https://$CSD_HOSTNAME/CACHE/sdesktop/hostscan/windows_i386/manifest"
call_curl 3 "$URL" $TOKEN > /dev/null
URL="https://$CSD_HOSTNAME/+CSCOT+/translation-table?type=mo&textdomain=csd&lang=en=us"
call_curl 3 "$URL" $TOKEN > /dev/null
URL="https://$CSD_HOSTNAME/+CSCOT+/translation-table?type=mo&textdomain=csd&lang=en"
call_curl 3 "$URL" $TOKEN > /dev/null

if [ -n "$XMLSTARLET" ]; then
    URL="https://$CSD_HOSTNAME/CACHE/sdesktop/data.xml"
    call_curl 6 "$URL" $TOKEN > /dev/null
    call_curl 3 "$URL" $TOKEN | xmlstarlet sel -t -v '/data/hostscan/field/@value' -n | while read -r ENTRY; do
	# XX: How are ' and , characters escaped in this?
	TYPE="$(sed "s/^'\(.*\)','\(.*\)','\(.*\)'$/\1/" <<< "$ENTRY")"
	NAME="$(sed "s/^'\(.*\)','\(.*\)','\(.*\)'$/\2/" <<< "$ENTRY")"
	VALUE="$(sed "s/^'\(.*\)','\(.*\)','\(.*\)'$/\3/" <<< "$ENTRY")"
	if [ "$TYPE" != "$ENTRY" ]; then
	    case "$TYPE" in
		File)
		    BASENAME="$(echo "$VALUE" | sed 's/\\/\//g')"
		    BASENAME="$(basename "$BASENAME")"
		    cat >> $RESPONSE <<EOF
endpoint.file["$NAME"]={};
EOF
		    case "$VALUE" in
			"Some value")
		            cat >> $RESPONSE <<EOF
endpoint.file["$NAME"].exists="false";
endpoint.file["$NAME"].path="$VALUE";
endpoint.file["$NAME"].name="$VALUE";
EOF
			    ;;
			"Some other value")
		            cat >> $RESPONSE <<EOF
endpoint.file["$NAME"].exists="true";
endpoint.file["$NAME"].path="$VALUE";
endpoint.file["$NAME"].name="$BASENAME";
endpoint.file["$NAME"].lastmodified="4910876";
endpoint.file["$NAME"].timestamp="1621347476";
EOF
			    ;;
			*)
			    echo "Unhandled hostscan file: '$NAME'/'$VALUE'"
			    ;;
		    esac
		    ;;

		Process)
		    echo "Unhandled hostscan process: '$NAME'/'$VALUE'"
		    ;;

		Registry)
		    cat >> $RESPONSE <<EOF
endpoint.registry["$NAME"]={};
EOF
		    case "$VALUE" in
			"Some value")
			    cat >> $RESPONSE <<EOF
endpoint.registry["$NAME"].exists="true";
endpoint.registry["$NAME"].path="$VALUE";
endpoint.registry["$NAME"].type="string";
endpoint.registry["$NAME"].value="BEUWH1233";
EOF
			    ;;
			"Some other value")
			    cat >> $RESPONSE <<EOF
endpoint.registry["$NAME"].exists="true";
endpoint.registry["$NAME"].path="$VALUE";
endpoint.registry["$NAME"].type="string";
endpoint.registry["$NAME"].value="mydomain.com";
EOF
			    ;;
			"Some another value")
			    cat >> $RESPONSE <<EOF
endpoint.registry["$NAME"].exists="false";
endpoint.registry["$NAME"].path="$VALUE";
EOF
			    ;;
			*)
			    echo "Unhandled hostscan registry: '$NAME'/'$VALUE'"
			    ;;
		    esac
		    ;;

		*)
		    echo "Unhandled hostscan element of type '$TYPE': '$NAME'/'$VALUE'"
		    ;;
	    esac
	else
	    echo "Unhandled hostscan field '$ENTRY'"
	fi
    done
fi

# based on real dump
URL="https://$CSD_HOSTNAME/+CSCOL+/opswatlicense.html"
call_curl 3 $URL $TOKEN > /dev/null
URL="https://$CSD_HOSTNAME/CACHE/sdesktop/hostscan/windows_i386/manifest"
call_curl 3 "$URL" $TOKEN > /dev/null

#sleep 3
CONTENT_HEADER="Content-Type: text/xml"
URL="https://$CSD_HOSTNAME/+CSCOE+/sdesktop/scan.xml?reusebrowser=1"
call_curl 5 $URL $TOKEN $RESPONSE >> $RESULT

cat $RESULT || :

# based on real dump
RESPONSE_CODE=200
COUNTER=0
URL="https://$CSD_HOSTNAME/+CSCOE+/sdesktop/wait.html"
while [ $RESPONSE_CODE -ne 302 ] ; do
    RESPONSE_CODE=$( call_curl 4 $URL $TOKEN )
    let COUNTER++
    if [ $COUNTER -eq 5 ]; then
        exit 2
    fi
    if [ $RESPONSE_CODE -eq 302 ]; then
        break;
    fi
#   sleep 2
done

exit 0
