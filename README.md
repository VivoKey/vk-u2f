VivoKey fork of the below
=========================

The end goal for this is that we implement CTAP2. Yes, this needs CBOR.

Customized U2F Applet
=====================

This is a fork of the [Ledger U2F Applet](https://github.com/LedgerHQ/ledger-u2f-javacard) that is focused on privacy and compatability. It has several unique features:

* Still works with JC 3.0.1 cards. (Probably not anymore - Riley)
* Supports iOS via NFC, by [working around a bug in Apple's FIDO2 implementation](https://github.com/darconeous/u2f-javacard/commit/8b58c4cdcae295977306d895c7d5afd7c5628a22).
* [Multiple counters (8)](https://github.com/darconeous/u2f-javacard/commit/554b0718cddf1eccc575bede16fb3f32cc44707e), which are assigned to registrations in a round-robin fashion.
* [EEPROM wear-leveling for counters](https://github.com/darconeous/u2f-javacard/commit/c2f223d69300a4227d8865b72b3d72158191afd6)
* [Supports "dont-enforce-user-presence-and-sign"](https://github.com/darconeous/u2f-javacard/commit/24b6f13f8c221771df6f087530574d222a71d6a1).

This fork also [fixes some problems with Extended APDUs](https://github.com/darconeous/u2f-javacard/commit/7a7dcc7329405061bce430061584a20724ff1eda) that is [present in the upstream version](https://github.com/LedgerHQ/ledger-u2f-javacard/pull/13).

If you want to just get a CAP file and install it, you can find it in the [releases section](https://github.com/darconeous/u2f-javacard/releases). Check the assets for the release, there should be a `U2FApplet.cap` and a `U2FApplet.cap.gpg`. The cap file is signed with [my public gpg key](https://keybase.io/darconeous).

Once you have a CAP file, you can use [this script](https://gist.github.com/darconeous/adb1b2c4b15d3d8fbc72a5097270cdaf) to install using [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro).

What follows below is from the original project README, with a few edits for things that have clearly changed.

--------------------------------------


# Overview

This applet is a Java Card implementation of the [FIDO Alliance U2F standard](https://fidoalliance.org/)

It uses no proprietary vendor API and is freely available on [Ledger Unplugged](https://www.ledgerwallet.com/products/6-ledger-unplugged) and for a small fee on other Fidesmo devices through [Fidesmo store](http://www.fidesmo.com/apps/4f97a2e9)

# Building 

  - Set the environment variable `JC_HOME` to the folder containg the [Java Card Development Kit 3.0.2](http://www.oracle.com/technetwork/java/embedded/javacard/downloads/index.html)
  - Run `gradlew convertJavacard`

# Installing 

Either load the CAP file using your favorite third party software or refer to [Fidesmo Gradle Plugin](https://github.com/fidesmo/gradle-javacard) to use on the Fidesmo platform

 
The following install parameters are expected : 

  - 1 byte flag : provide 01 to pass the current [Fido NFC interoperability tests](https://github.com/google/u2f-ref-code/tree/master/u2f-tests), or 00 *(You almost certainly want to pass in 00)*
  - 2 bytes length (big endian encoded) : length of the attestation certificate to load, supposed to be using a private key on the P-256 curve 
  - 32 bytes : private key of the attestation certificate 

Before using the applet, the attestation certificate shall be loaded using a proprietary APDU 

| CLA | INS | P1            | P2           | Data                    |
| --- | --- | ------------- | ------------ | ----------------------- |
| 80  | 01  | offset (high) | offset (low) | Certificate data chunk  | 

# Testing on Android 

  - Download [Google Authenticator](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2)
  - Test on http://u2fdemo.appspot.com or https://demo.yubico.com/u2f from Chrome
  - For additional API reference and implementations, check [the reference code](https://github.com/google/u2f-ref-code), the [beta NFC API](https://github.com/google/u2f-ref-code/blob/no-extension/u2f-gae-demo/war/js/u2f-api.js) and [Yubico guide](https://www.yubico.com/applications/fido/) 

# Certification

This implementation has been certified FIDO U2F compliant on December 17, 2015 (U2F100020151217001). See tag [u2f-certif-171215](https://github.com/LedgerHQ/ledger-u2f-javacard/tree/u2f-certif-171215)
  
# License

This application is licensed under [Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0)

# Contact

~~Please contact hello@ledger.fr for any question~~

