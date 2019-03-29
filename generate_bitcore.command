#!/bin/sh
# TODO: generate minified
cd "$(dirname "$0")"

if [ "$UID" -ne 0 ]
  then echo "Poor Npm needs sudo"
  exit
fi

rm -rf bitcore-lib-cash/
git clone https://github.com/bitpay/bitcore.git
cd bitcore
#patch 2 is required!
git apply -v ../bitcore-cash-02.patch
#patch 3 might not be required
git apply -v ../bitcore-cash-03.patch
#patch 5 makes things easier
git apply -v ../bitcore-cash-05.patch
cd packages/bitcore-lib-cash/
#Phantomjs needs perms
sudo npm i --unsafe-perm
license-checker --out=open-source-licenses.txt --relativeLicensePath #--production
rm bitcore-lib.js bitcore-lib.min.js
gulp browser
mv open-source-licenses.txt ../../../open-source-licenses.txt
mv bitcore-lib.js ../../../bitcore-lib-full.js
#mv bitcore-lib.min.js ../../../bitcore-lib.js
cd ../../..
rm -rf bitcore/
