
Code status:
------------

## TrustSQL: World 1st distributed ledger function enabled RDBMS

TrustSQL is designed as a node application in distributed ledger environment.
It replace peer application like as Bitcoin daemon or Ethreum daemon.
RDBMS is quite advanced data management method. Now you can use it on distributed ledger system with all features of RDBMS.

The base of TrustSQL is MariaDB v10.3.11.
It works same with MariaDB also because TrustSQL doens't remove any features of MariaDB.
TrustSQL just add some features for blockchain on MariaDB.

Now, all applcation developers on RDBMS can be blockchain or distributed ledger application developers with ease.
You just need very little efforts to understand how the TrustSQL makes trust on RDBMS
With detail, you have to learn how to design data schema to be trusted with additional constraints for trust.


Build:
--------

#### build essentials

Refer followings for UBUNTU
sudo apt-get install build-essential libtool  autotools-dev autoconf  pkg-config  libssl-dev
sudo apt install cmake
sudo apt-get install libaio1
sudo apt-get install gnutls-dev
sudo apt-get install libjemalloc-dev
sudo apt install libgnutls-dev
sudo apt-get install libncurses5-dev
sudo apt-get install bison
sudo apt install librocksdb-dev
apt-get install -y zlib1g-dev
sudo apt-get update
sudo apt-get upgrade

#### secp256k1 library
git clone https://github.com/urbit/secp256k1
./authogen.sh
./configure --enable-jni --enable-experimental --enable-module-schnorr --enable-module-ecdh
make
sudo make install

#### TrustSQL build
The following command builds a server the same way that is used for building releases. Use  `cmake . -DCMAKE_TRUSTSQL_BUILD=RELEASE`  to build for debugging.
cmake . -DCMAKE_TRUSTSQL_BUILD=RELEASE && make -j8

If you do not put the option, it works as a MariaDB server.
You can find my example in file cmake_trustsql



Who we are:
----------
TrustDB inc, is a distributed ledger technology company in South, Korea.
 

Help:
-----
If you need any help please send me an e-mail.
booltaking@gmail.com


License:
--------

***************************************************************************

NOTE: 

TrustSQL is specifically available only under version 2 of the GNU
General Public License (GPLv2). (I.e. Without the "any later version"
clause.) This is inherited from MariaDB.

***************************************************************************
