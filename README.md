# Overview

[![Build Status](https://github.com/duosecurity/duo_client_java/workflows/Java%20CI/badge.svg?branch=master)](https://github.com/duosecurity/duo_client_java/actions)
[![Issues](https://img.shields.io/github/issues/duosecurity/duo_client_java)](https://github.com/duosecurity/duo_client_java/issues)
[![Forks](https://img.shields.io/github/forks/duosecurity/duo_client_java)](https://github.com/duosecurity/duo_client_java/network/members)
[![Stars](https://img.shields.io/github/stars/duosecurity/duo_client_java)](https://github.com/duosecurity/duo_client_java/stargazers)
[![License](https://img.shields.io/badge/License-View%20License-orange)](https://github.com/duosecurity/duo_client_java/blob/master/LICENSE)

**duo_client** - Demonstration client to call Duo API methods
with Java.

## Tested Against Java Versions:
* 8
* 11
* 17

## TLS 1.2 and 1.3 Support

Duo_client_java uses the Java cryptography libraries for TLS operations.  Both TLS 1.2 and 1.3 are supported by Java 8 and later versions.  

# Duo Auth API

The Duo Auth API provides a low-level API for adding strong two-factor
authentication to applications that cannot directly display rich web
content.

For more information see the Duo Auth API guide:

<https://www.duosecurity.com/docs/authapi>

# Duo Admin API

The Duo Admin API provides programmatic access to the administrative
functionality of Duo Security's two-factor authentication platform.
This feature is not available with all Duo accounts.

For more information see the Duo Admin API guide:

<http://www.duosecurity.com/docs/adminapi>

# Duo Accounts API

The Duo Accounts API allows a parent account to create, manage, and
delete other Duo customer accounts. This feature is not available with
all Duo accounts.

For more information see the Duo Accounts API guide:

<http://www.duosecurity.com/docs/accountsapi>

# Usage

The Java API Client project is available from Duo Security on Maven.  Include the following in your dependency definitions:
```

<!-- https://central.sonatype.com/artifact/com.duosecurity/duo-client -->
<dependency>
    <groupId>com.duosecurity</groupId>
    <artifactId>duo-client</artifactId>
    <version>0.9.0</version>
</dependency>
```

See https://central.sonatype.com/artifact/com.duosecurity/duo-client/0.9.0 for more details.

## Verifying releases

Artifacts published to Maven Central are signed with one of Duo's Maven signing keys.
The public keys are in [`KEYS`](KEYS) in this repository.

```
curl -O https://raw.githubusercontent.com/duosecurity/duo_client_java/master/KEYS
gpg --import KEYS
gpg --verify duo-client-0.9.0.jar.asc duo-client-0.9.0.jar
```

The `.jar.asc` signature files are available alongside each artifact on Maven Central,
for example <https://repo1.maven.org/maven2/com/duosecurity/duo-client/0.9.0/>.

| Versions | Key fingerprint |
| --- | --- |
| 0.8.0 and later | `7ED4 A780 3AFC 6DE8 47DF  9A3F 70EE 73F2 1701 2D0E` |
| 0.3.0 through 0.7.1 | `20FF 0D66 B2D0 202C 1544  7339 7E77 F31E 27A4 AEA2` (expired 2026-01-27) |

A `Good signature` result confirms the artifact was signed with a Duo key. GPG also
reports the key as untrusted unless you have signed it yourself, and reports the
retired key as expired; neither affects the validity of signatures made while that
key was valid.

# Using the Example
There is an example in /duo-example-admin
Create an Admin API application in your Duo Admin Panel.
To set the minimum permissions, under your API's 'Permissions', check the three boxes that start with "Grant read ...".
```
$ java -jar duo-example-admin-0.9.0-jar-with-dependencies.jar -host <host> -ikey <ikey> -skey <skey>
```
If successful, the console will print the users and authentication attempts.


# Testing

```
$ mvn test
```

# Linting

```
$ mvn checkstyle:check
```
