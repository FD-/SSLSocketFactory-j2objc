///
/// iOSSSLSocketFactory.swift
///
/// An SSLSocketFactory for j2objc that uses the native iOS SecureTransport API
///
/// - Author: Florian Draschbacher
/// - Copyright: © 2018 Florian Draschbacher. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
/// http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

import Foundation
import Security

private func throwIOException(description: String, status: OSStatus){
  var statusDescription = "Error \(status)"
  if #available(iOS 11.3, *) {
    statusDescription = SecCopyErrorMessageString(status, nil)! as String
  }
  
  ObjC.throwException(JavaIoIOException(nsString: description + String(status) +
    " - " + statusDescription))
}

class iOSSSLInputStream : JavaIoInputStream {
  unowned let sslSocket : iOSSSLSocket
  
  init(sslSocket : iOSSSLSocket) {
    self.sslSocket = sslSocket
    super.init()
  }
  
  override func read(with b: IOSByteArray!, with off: jint, with len: jint) -> jint {
    if (sslSocket.isClosed() || (sslSocket.underlyingSocket?.isClosed())!){
      ObjC.throwException(JavaIoIOException(nsString: "Cannot read from closed socket"))
    }
    
    if (sslSocket.isInputShutdown() || (sslSocket.underlyingSocket?.isInputShutdown())!){
      ObjC.throwException(JavaIoIOException(nsString: "Cannot read from shutdown socket"))
    }
    
    let bufferPointer = UnsafeMutableRawPointer(b.byteRef(at: UInt(off)))
    var actuallyRead : Int = 0
    let status = SSLRead(sslSocket.getSSLContext()!, bufferPointer!, Int(len),
                         &actuallyRead)
    if (status == errSecSuccess || status == errSSLWouldBlock){
      return jint(actuallyRead)
    } else {
      throwIOException(description: "Error reading from SSL: ", status: status)
    }
    return jint(actuallyRead)
  }
  
  override func read(with b: IOSByteArray!) -> jint {
    return read(with: b, with: 0, with: b.length())
  }
  
  override func read() -> jint {
    let buffer = IOSByteArray.newArray(withLength: 1)
    let actuallyRead = read(with: buffer)
    if (actuallyRead == 1) {
      let resultByte : jbyte = (buffer?.byte(at: 0))!
      return jint(resultByte)
    } else {
      return actuallyRead
    }
  }
  
  override func close() {
    sslSocket.close()
  }
  
  override func available() -> jint {
    // Not supported
    return 0;
  }
  
  override func mark(with readlimit: jint) {
    // Not supported
  }
  
  override func markSupported() -> jboolean {
    return false
  }
  
  override func reset() {
    // Not supported
  }
  
  override func skip(withLong n: jlong) -> jlong {
    // Not supported
    return 0
  }
}

class iOSSSLOutputStream : JavaIoOutputStream {
  unowned let sslSocket : iOSSSLSocket
  
  init(sslSocket : iOSSSLSocket) {
    self.sslSocket = sslSocket
    super.init()
  }
  
  override func write(with b: IOSByteArray!, with off: jint, with len: jint) {
    if (sslSocket.isClosed() || (sslSocket.underlyingSocket?.isClosed())!){
      ObjC.throwException(JavaIoIOException(nsString: "Cannot write to closed socket"))
    }
    
    if (sslSocket.isOutputShutdown() || (sslSocket.underlyingSocket?.isOutputShutdown())!){
      ObjC.throwException(JavaIoIOException(nsString: "Cannot write to shutdown socket"))
    }
    
    var bufferPointer = UnsafeMutableRawPointer(b.byteRef(at: UInt(off)))
    var actuallyWritten : Int = 0
    var remaining : Int = Int(len);
    
    while remaining > 0 {
      let status = SSLWrite(sslSocket.getSSLContext()!, bufferPointer, remaining,
                            &actuallyWritten)
      if (status == noErr || status == errSSLWouldBlock){
        bufferPointer = bufferPointer?.advanced(by: actuallyWritten)
        remaining -= actuallyWritten
      } else {
        throwIOException(description: "Error writing to SSL: ", status: status)
      }
    }
  }
  
  override func write(with b: IOSByteArray!) {
    write(with: b, with: 0, with: b.length())
  }
  
  override func write(with b: jint) {
    let buffer = IOSByteArray.newArray(withLength: 1)
    buffer?.replaceByte(at: 0, withByte: jbyte(b))
    write(with: buffer)
  }
  
  override func close() {
    sslSocket.close()
  }
  
  override func flush() {
    // The framework keeps an SSL cache. Whenever a call to SSLWrite returns
    // errSSLWouldBlock, the data has been copied to the cache, but not yet
    // (completely) sent. In order to flush this cache, we have to call
    // SSLWrite on an empty buffer
    
    var status : OSStatus
    var actuallyWritten : Int = 0
    
    repeat {
      status = SSLWrite(sslSocket.getSSLContext()!, nil, 0, &actuallyWritten)
    } while status == errSSLWouldBlock
    
    sslSocket.getUnderlyingSocket().getOutputStream().flush()
  }
}

class iOSSSLSocket : WrappedSSLSocket{
  var sslContext : SSLContext?
  var inputStream : iOSSSLInputStream?
  var outputStream : iOSSSLOutputStream?
  var underlyingSocket : JavaNetSocket?
  
  init(underlyingSocket: JavaNetSocket, hostName: String) {
    self.underlyingSocket = underlyingSocket
    self.sslContext = SSLCreateContext(nil, SSLProtocolSide.clientSide,
                                       SSLConnectionType.streamType)
  
    super.init(javaNetSocket: underlyingSocket)
    
    self.inputStream = iOSSSLInputStream(sslSocket: self)
    self.outputStream = iOSSSLOutputStream(sslSocket: self)
  
    var status = noErr
    status = SSLSetIOFuncs(sslContext!, sslReadCallback, sslWriteCallback)
    if (status != noErr) {
      throwIOException(description: "Error setting IO functions: ", status: status)
    }
    
    let connectionRef : SSLConnectionRef = UnsafeRawPointer(
      Unmanaged.passUnretained(self).toOpaque())
    status = SSLSetConnection(sslContext!, connectionRef)
    if (status != noErr) {
      throwIOException(description: "Error setting connection data: ", status: status)
    }
    
    status = SSLSetPeerDomainName(sslContext!, hostName,
                                  hostName.lengthOfBytes(using: String.Encoding.utf8))
    if (status != noErr) {
      throwIOException(description: "Error setting domain name: ", status: status)
    }
  }
  
  override func startHandshake() {
    var status = noErr
    
    repeat {
      status = SSLHandshake(sslContext!)
    } while status == errSSLWouldBlock
    
    if (status != noErr) {
      throwIOException(description: "Handshake error: ", status: status)
    }
  }
  
  func getSSLContext() -> SSLContext?{
    return sslContext
  }
  
  override func close() {
    if (isClosed()) {
      ObjC.throwException(JavaIoIOException(nsString: "Already closed"))
    }
    
    SSLClose(sslContext!)
    underlyingSocket?.close()
  }
  
  override func getInputStream() -> JavaIoInputStream! {
    return inputStream
  }
  
  override func getOutputStream() -> JavaIoOutputStream! {
    return outputStream
  }
}

private func sslReadCallback(connection: SSLConnectionRef, data: UnsafeMutableRawPointer,
                             dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
  let socket = Unmanaged<iOSSSLSocket>.fromOpaque(connection).takeUnretainedValue()
  
  let javaByteBuffer = IOSByteArray.newArray(withLength: UInt(dataLength.pointee))
  var status = noErr
  
  do {
    try ObjC.catchException {
      let askedToRead = dataLength.pointee
      let actuallyRead = socket.getUnderlyingSocket().getInputStream()
        .read(with: javaByteBuffer)
      
      if actuallyRead > 0 {
        let jbytePointer = data.bindMemory(to: jbyte.self, capacity: dataLength.pointee)
        javaByteBuffer?.getBytes(jbytePointer, length:UInt(actuallyRead))
        dataLength.pointee = Int(actuallyRead)
        // Important: Return errSSLWouldBlock if we didn't read exactly as much as requested
        status = actuallyRead < askedToRead ? errSSLWouldBlock : noErr
      } else {
        status = errSSLClosedAbort
      }
    }
  } catch {
    status = errSSLClosedAbort
  }
  
  return status
}

private func sslWriteCallback(connection: SSLConnectionRef, data: UnsafeRawPointer,
                              dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
  let socket = Unmanaged<iOSSSLSocket>.fromOpaque(connection).takeUnretainedValue()
  
  let jbytePointer = data.bindMemory(to: jbyte.self, capacity: dataLength.pointee)
  let javaByteBuffer = IOSByteArray.newArray(withBytes:jbytePointer,
                                             count: UInt(dataLength.pointee))
  
  do {
    try ObjC.catchException {
      socket.getUnderlyingSocket().getOutputStream().write(with: javaByteBuffer)
      socket.getUnderlyingSocket().getOutputStream().flush()
    }
  } catch {
    return errSSLClosedAbort
  }
  return noErr
}

class iOSSSLSocketFactory : JavaxNetSslSSLSocketFactory{
  override func createSocket(with s: JavaNetSocket!, with host: String!,
                             with port: jint, withBoolean autoClose: jboolean) -> JavaNetSocket! {
    return iOSSSLSocket(underlyingSocket: s, hostName: host)
  }
  
  override func createSocket() -> JavaNetSocket! {
    // Not implemented
    return nil
  }
  
  override func createSocket(with host: String!, with port: jint) -> JavaNetSocket! {
    // Not implemented
    return nil
  }
  
  override func getSupportedCipherSuites() -> IOSObjectArray! {
    // Not implemented
    return nil
  }
  
  override func getDefaultCipherSuites() -> IOSObjectArray! {
    // Not implemented
    return nil
  }
}
