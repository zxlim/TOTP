# TOTP [![](https://jitpack.io/v/zxlim/TOTP.svg)](https://jitpack.io/#zxlim/TOTP)

A server-side Java implementation of Time-based One-Time Password (TOTP) based on the [RFC 6238 standard](https://tools.ietf.org/html/rfc6238).
<br>
Tested with Google Authenticator, but should also work with any two-step verification services that implements the algorithms stated in RFC 6238.
<br><br>

## Dependencies

- Apache Commons Codec
<br><br>

## Instructions

To include this in your project, add it as a dependency in build.gradle:
```
repositories {
    mavenCentral()
    maven {
    	url 'https://jitpack.io'
    }
}

dependencies {
    //...
    compile 'com.github.zxlim:TOTP:master-SNAPSHOT'
}
```
<br><br><br><br>

## License/ Copyright Information

This project is released under version 2.0 of the Apache License. You may read the terms [here](LICENSE).
