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
    let bufferPointer = UnsafeMutableRawPointer(b.byteRef(at: UInt(off)))
    var actuallyRead : Int = 0
    var status = noErr
    
    repeat {
      status = SSLRead(sslSocket.getSSLContext()!, bufferPointer!, Int(len), &actuallyRead)
    } while status == errSSLWouldBlock && actuallyRead == 0
    
    if (status == errSecSuccess || status == errSSLWouldBlock){
      return jint(actuallyRead)
    } else {
      if let exception = sslSocket.underlyingException {
        ObjC.throwException(exception)
      }
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
      let resultByte: jbyte = (buffer?.byte(at: 0))!
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
    ObjC.throwException(JavaIoIOException(nsString: "Available is not supported"))
    return -1;
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
    var bufferPointer = UnsafeMutableRawPointer(b.byteRef(at: UInt(off)))
    var actuallyWritten: Int = 0
    var remaining: Int = Int(len);
    
    while (remaining > 0) {
      let status = SSLWrite(self.sslSocket.getSSLContext()!, bufferPointer, remaining,
                            &actuallyWritten)
      if (status == noErr || status == errSSLWouldBlock){
        bufferPointer = bufferPointer?.advanced(by: actuallyWritten)
        remaining -= actuallyWritten
      } else {
        if let exception = sslSocket.underlyingException {
          ObjC.throwException(exception)
        }
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
    // The framework keep an SSL caches for reading and writing.
    // Whenever a call to SSLWrite returns errSSLWouldBlock, the data has been
    // copied to the cache, but not yet (completely) sent. In order to flush
    // this cache, we have to call SSLWrite on an empty buffer.
    
    var status : OSStatus
    var actuallyWritten : Int = 0
    
    repeat {
      status = SSLWrite(sslSocket.getSSLContext()!, nil, 0, &actuallyWritten)
    } while (status == errSSLWouldBlock)
    
    sslSocket.getUnderlyingSocket().getOutputStream().flush()
  }
}

class iOSSSLSocket: UVDWrappedSSLSocket{
  var sslContext: SSLContext?
  var inputStream: iOSSSLInputStream?
  var outputStream: iOSSSLOutputStream?
  var underlyingSocket: JavaNetSocket?
  var underlyingException: JavaLangException?
  
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
    
    let status = SSLClose(sslContext!)
    if (status != noErr) {
      throwIOException(description: "Closing error: ", status: status)
    }
    
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
  var status = noErr
  
  do {
    // The SecureTransport API sometimes requests data from the
    // callback even if it still has application data in its buffer. If we would
    // blindly read from the underlying (blocking) socket in that case, the
    // application layer would only get the data from the SecureTransport buffer
    // after the blocking read on the underlying socket returns, which in some
    // cases means we'd have to wait for the timeout to kick in.
    // By letting the SecureTransport API know we don't have any more data
    // at this point, we can force it to deplete its internal buffer of application
    // data.
    var available: jint = -1
    do {
      try ObjC.catchException {
        available = socket.getUnderlyingSocket().getInputStream().available()
      }
    } catch {}
    
    if (available == 0) {
      // The underlying socket supports available() and reported that no data is
      // available.
      dataLength.pointee = 0
      status = errSSLWouldBlock
    } else {
      try ObjC.catchException {
        let askedToRead = dataLength.pointee
        let javaByteBuffer = IOSByteArray.newArray(withLength: UInt(dataLength.pointee))
        let actuallyRead = socket.getUnderlyingSocket().getInputStream().read(with: javaByteBuffer)
        
        if (actuallyRead == 0) {
          // This case shouldn't actually happen
          dataLength.pointee = 0
          status = errSSLWouldBlock
        } else if (actuallyRead > 0) {
          let jbytePointer = data.bindMemory(to: jbyte.self, capacity: dataLength.pointee)
          javaByteBuffer?.getBytes(jbytePointer, length:UInt(actuallyRead))
          dataLength.pointee = Int(actuallyRead)
          // Important: Return errSSLWouldBlock if we didn't read exactly as much as requested
          status = actuallyRead < askedToRead ? errSSLWouldBlock : noErr
        } else {
          status = errSSLClosedAbort
        }
      }
    }
  } catch let error as NSError {
    if let exception = error.userInfo["exception"] {
      socket.underlyingException = exception as? JavaLangException
    }
    status = errSSLInternal
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
  } catch let error as NSError {
    if let exception = error.userInfo["exception"] {
      socket.underlyingException = exception as? JavaLangException
    }
    return errSSLInternal
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
