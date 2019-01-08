#!/bin/bash
# nse-parse.sh
# v1.0 - 01/08/2018 by Ted R (http://github.com/actuated)
# Script to parse stdout Nmap NSE results, supporting multiple NSEs
# Reads each line of the input to find the current host, current NSE, and if a result was VULNERABLE or LIKELY VULNERABLE
# Gives totals and creates lists of affected hosts
varDateCreated="01/08/2018"
varDateLastMod="01/08/2018"

inFile="$1"
tempYMDHM=$(date +%F-%H-%M)
tempFile="nsep-temp-$tempYMDHM.txt"
outDir="."

function fnUsage {
  echo
  echo "======================================[ about ]======================================"
  echo
  echo "Parse Nmap NSE scan results (stdout/.nmap output) into lists of affected hosts for"
  echo "each NSE. "
  echo
  echo "Finds VULNERABLE or LIKELY VULNERABLE states for NSEs with [A-Za-z0-9-] names."
  echo
  echo "Created $varDateCreated, last modified $varDateLastMod."
  echo
  echo "======================================[ usage ]======================================"
  echo
  echo "./nse-parse.sh [input file] [--out-dir [dir]]"
  echo
  echo "--out-dir [path]       Optionally specify a directory for output files."
  echo "                       The default is the current directory."
  echo
  echo "=======================================[ fin ]======================================="
  echo
  exit
}

function fnParseToCSV {
  echo
  totalLines=$(wc -l "$inFile" | awk '{print $1}')
  thisCount=0
  while read thisLine; do
    let thisCount=thisCount+1
    echo -ne "Parsing line $thisCount of $totalLines in $inFile            "\\r
    checkForHost=$(echo "$thisLine" | grep 'Nmap scan report for' | awk '{print $NF}' | tr -d '()')
    if [ "$checkForHost" != "" ]; then thisHost="$checkForHost"; fi
    checkForNSE=$(echo "$thisLine" | grep '|[ _][A-Za-z0-9-]*:' | awk -F: '{print $1}' | tr -d '| _:')
    if [ "$checkForNSE" != "" ]; then thisNSE="$checkForNSE"; fi
    checkForState=$(echo "$thisLine" | grep 'State: VULNERABLE\|State: LIKELY VULNERABLE' | awk -F: '{print $2}' | sed 's/^ //g')
    if [ "$checkForState" != "" ]; then
      thisState="$checkForState"
      echo "$thisNSE,$thisHost,$thisState" >> "$tempFile"
    fi  
  done < "$inFile"
  echo
}

function fnParseFromCSV {
  if [ -f "$tempFile" ]; then
    echo
    echo "Parsing CSV results from temp file $tempFile..."

    if [ -d "$outDir" ]; then
      echo
      echo "FYI: Output directory $outDir exists."
      echo "Files named [nse]-[state]-hosts.txt may be appended."
    fi

    echo
    for thisNSE in $(awk -F, '{print $1}' "$tempFile" | sort | uniq); do
      if [ ! -d "$outDir" ]; then mkdir "$outDir"; fi
      checkState=$(grep "^$thisNSE," "$tempFile" | grep ",VULNERABLE")
      if [ "$checkState" != "" ]; then
        grep "^$thisNSE," "$tempFile" | grep ",VULNERABLE" | awk -F, '{print $2}' | sort -V | uniq | grep . >> "$outDir/$thisNSE-vulnerable-hosts.txt"
      fi
      checkState=$(grep "^$thisNSE," "$tempFile" | grep "LIKELY VULNERABLE")
      if [ "$checkState" != "" ]; then
        grep "^$thisNSE," "$tempFile" | grep ",LIKELY VULNERABLE" | awk -F, '{print $2}' | sort -V | uniq | grep . >> "$outDir/$thisNSE-likely-vulnerable-hosts.txt"
      fi
      wc -l "$outDir/$thisNSE"-* | sed "s/$outDir\///g"
    done

    if [ -f "$tempFile" ]; then rm "$tempFile"; fi

    if [ "$outDir" != "." ]; then
      echo
      echo "Output files written in $outDir/"
    fi

  else
    echo
    echo "Error: No results to parse. Check input file to see if there were results."
    echo "Hosts are found by grepping for 'Nmap scan report for'."
    echo "NSE names are found by grepping for '|[ _][A-Za-z0-9-]*:'."
    echo "Results are found by grepping for 'State: VULNERABLE\|State: LIKELY VULNERABLE'."
  fi
}

echo
echo "=====================[ nse-parse.sh - Ted R (github: actuated) ]====================="

if [ -f "$1" ]; then
  inFile="$1"
  shift
else
  echo
  echo "Error: Input file '$1' does not exist."
  fnUsage
fi

while [ "$1" != "" ]; do
  case "$1" in
    --out-dir )
      shift
      outDir="$1"
      if [ "$outDir" = "" ]; then
        echo
        echo "Error: Output directory option specified but not value provided."
        fnUsage
      fi
      ;;
    -h|--help )
      fnUsage
      ;;
    * )
      echo
      echo "Error: Unknown argument entered."
      fnUsage
      ;;
  esac
  shift
done

fnParseToCSV
fnParseFromCSV

echo
echo "=======================================[ fin ]======================================="
echo

