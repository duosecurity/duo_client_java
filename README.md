# Overview

[![Build Status](https://github.com/duosecurity/duo_client_java/workflows/Java%20CI/badge.svg?branch=master)](https://github.com/duosecurity/duo_client_java/actions)
[![Issues](https://img.shields.io/github/issues/duosecurity/duo_client_java)](https://github.com/duosecurity/duo_client_java/issues)
[![Forks](https://img.shields.io/github/forks/duosecurity/duo_client_java)](https://github.com/duosecurity/duo_client_java/network/members)
[![Stars](https://img.shields.io/github/stars/duosecurity/duo_client_java)](https://github.com/duosecurity/duo_client_java/stargazers)
[![License](https://img.shields.io/badge/License-View%20License-orange)](https://github.com/duosecurity/duo_client_java/blob/master/LICENSE)

**duo_client** - Demonstration client to call Duo API methods
with Java.

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

<!-- https://mvnrepository.com/artifact/com.duosecurity/duo-client -->
<dependency>
    <groupId>com.duosecurity</groupId>
    <artifactId>duo-client</artifactId>
    <version>0.4.0</version>
</dependency>
```

See https://mvnrepository.com/artifact/com.duosecurity/duo-client/0.4.0 for more details.

# Using the Example
There is an example in /duo-example-admin
Create an Admin API application in your Duo Admin Panel. 
To set the minimum permissions, under your API's 'Permissions', check the three boxes that start with "Grant read ...".
```
$ java -jar duo-example-admin-0.4.0-jar-with-dependencies.jar -host <host> -ikey <ikey> -skey <skey>
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
