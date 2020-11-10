# Overview

[![Build Status](https://github.com/duosecurity/duo_client_java/workflows/Java%20CI/badge.svg?branch=master)](https://github.com/duosecurity/duo_client_java)
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

The Java API Client project is not currently available from Duo Security on Maven.  Currently this GitHub project is the only supported source for the Duo Java API Client.

# Testing

```
$ mvn test
```

# Linting

```
$ mvn checkstyle:check
```
