Scootercoin Core
=============

Intro
-----
Scootercoin is a free open source peer-to-peer electronic cash system that is
completely decentralized, without the need for a central server or trusted
parties.  Users hold the crypto keys to their own money and transact directly
with each other, with the help of a P2P network to check for double-spending.


Setup
-----
Choose the win64 download for 64-bit Windows. The win32 download is intended for
32-bit systems; limited address space may require smaller caches, for example
-dbcache=100 -maxmempool=50. Prefer win64 whenever possible.

Use the setup executable to install, or unpack the portable ZIP into a directory
and run bin\scootercoin-qt.exe. Keep all files from the package together.
Verify the downloaded file against the release's SHA256SUMS before use.

Before upgrading, back up your wallet privately, close the old application and
wait for it to exit completely. Never run two processes on the same data directory.

Scootercoin Core is the original Scootercoin client and it builds the backbone of the network.
However, it downloads and stores the entire history of Scootercoin transactions;
depending on the speed of your computer and network connection, the synchronization
process can take anywhere from a few hours to a day or more.

Project information: https://scootercoin.org/
Block explorer: https://explorer.scootercoin.org/
Source, releases and issues: https://github.com/ScooterCoinWallet/wallet-pos

Third-party software
--------------------
The graphical application uses Qt under LGPL version 3. Its license texts are
in doc\third-party. Other dependency licenses and copyright notices are included
in doc\third-party\NOTICES.txt. The release provides the corresponding application source,
dependency source archives and build recipes. You may modify Qt and rebuild or
relink the application; no signing key is required to run your own build.
See doc\build-windows.md for cross-compilation instructions. The application
source retains its MIT license; dependencies retain their own licenses.
