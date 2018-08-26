# SSLSocketFactory-j2objc
An SSLSocketFactory for j2objc that uses the native iOS [SecureTransport API](https://developer.apple.com/documentation/security/secure_transport). My implementation is in Swift, because I set up the j2objc-generated code as a static library that I use from within a Swift project. In that Swift project, I then create an `iOSSSLSocketFactory` that I pass to a function of the j2objc-generated code, where the original Java code uses it to create `SSLSockets`.

# Functionality
The provided `SSLSocketFactory` works, but it doesn't provide any customisability. The SecureTransport API's default values are used for any parameters. This means it works for the most common scenarios, for example when you have to use an `SSLSocket` for connecting to an HTTPS server.
I successfully use it with a slightly stripped-down version of OkHttp that I ported. In particular, as the required lower-level components are not bridged into the Java layer, I had to remove support for `HostnameVerifier`, and `CertificatePinner` (from OkHttp). 

# Overhead
Luckily, the iOS SecureTransport API is sufficiently low-level that it doesn't impose any specific threading pattern. This means that we only have a little overhead for creating an `IOSByteArray` when we need to call a function that doesn't accept a raw pointer. In particular, when reading from the underlying Socket, we have to create a new `IOSByteArray` to pass to the `Socket.getInputStream()`'s read function and later copy the data back into the native buffer.

# Possible Improvements
This implementation only includes rather basic error handling. Although error descriptions are included where available, any kind of error is thrown as an `IOException`, which means the Java layer cannot distinguish between different error causes.

For fully bridging SecureTransport's functionality into Java, the best approach would probably be to implement a Java SSLEngine on top of SecureTransport. The `SSLSocket` could then be reimplemented to use this engine. I think the [Conscrypt project](https://github.com/google/conscrypt) implemented a similar `SSLSocket`.

The SecureTransport API should provide all functionality that is needed. For implementing custom certificate handling (eg hostname verification, pinning), the native `SSLContext` can be set to break during the handshake by setting the corresponding option. I guess it's possible to retrieve the server's certificate from there, but I'm not sure how that certificate would be bridged into Java. That's as much as I've learned from putting together pieces of information I gathered online while implementing the basic `SSLSocketFactory`.

# Resources
Unfortunately, the official documentation for the SecureTransport API doesn't really provide much information. Luckily, there are a few open source projects that documented their findings while implementing support for the SecureTransport API. Some projects I found useful were:

 - https://github.com/IBM-Swift/BlueSSLService
 - VLC's SecureTransport code: https://github.com/videolan/vlc/blob/master/modules/misc/securetransport.c
 - https://opensource.apple.com/source/Security/Security-55471/libsecurity_ssl/lib/SecureTransport.h.auto.html provides a mapping from error code numbers to short descriptions
 - Chromium SecureTransport code (very entertaining documentation): https://github.com/adobe/chromium/blob/master/net/socket/ssl_client_socket_mac.cc
