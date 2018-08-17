/*
 * WrappedSSLSocket.java
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

public class WrappedSSLSocket extends SSLSocket {
    protected Socket underlyingSocket;

    public WrappedSSLSocket(Socket underlying){
        this.underlyingSocket = underlying;
    }

    public Socket getUnderlyingSocket(){
        return underlyingSocket;
    }

    public void connect(SocketAddress endpoint) throws IOException {
        throw new RuntimeException("Stub!");
    }

    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        underlyingSocket.connect(endpoint, timeout);
    }

    public void bind(SocketAddress bindpoint) throws IOException {
        underlyingSocket.bind(bindpoint);
    }

    public InetAddress getInetAddress() {
        return underlyingSocket.getInetAddress();
    }

    public InetAddress getLocalAddress() {
        return underlyingSocket.getLocalAddress();
    }

    public int getPort() {
        return underlyingSocket.getPort();
    }

    public int getLocalPort() {
        return underlyingSocket.getLocalPort();
    }

    public SocketAddress getRemoteSocketAddress() {
        return underlyingSocket.getRemoteSocketAddress();
    }

    public SocketAddress getLocalSocketAddress() {
        return underlyingSocket.getLocalSocketAddress();
    }

    public SocketChannel getChannel() {
        return underlyingSocket.getChannel();
    }

    public InputStream getInputStream() throws IOException {
        return underlyingSocket.getInputStream();
    }

    public OutputStream getOutputStream() throws IOException {
        return underlyingSocket.getOutputStream();
    }

    public void setTcpNoDelay(boolean on) throws SocketException {
        underlyingSocket.setTcpNoDelay(on);
    }

    public boolean getTcpNoDelay() throws SocketException {
        return underlyingSocket.getTcpNoDelay();
    }

    public void setSoLinger(boolean on, int linger) throws SocketException {
        underlyingSocket.setSoLinger(on, linger);
    }

    public int getSoLinger() throws SocketException {
        return underlyingSocket.getSoLinger();
    }

    public void sendUrgentData(int data) throws IOException {
        underlyingSocket.sendUrgentData(data);
    }

    public void setOOBInline(boolean on) throws SocketException {
        underlyingSocket.setOOBInline(on);
    }

    public boolean getOOBInline() throws SocketException {
        return underlyingSocket.getOOBInline();
    }

    public synchronized void setSoTimeout(int timeout) throws SocketException {
        underlyingSocket.setSoTimeout(timeout);
    }

    public synchronized int getSoTimeout() throws SocketException {
        return underlyingSocket.getSoTimeout();
    }

    public synchronized void setSendBufferSize(int size) throws SocketException {
        underlyingSocket.setSendBufferSize(size);
    }

    public synchronized int getSendBufferSize() throws SocketException {
        return underlyingSocket.getSendBufferSize();
    }

    public synchronized void setReceiveBufferSize(int size) throws SocketException {
        underlyingSocket.setSendBufferSize(size);
    }

    public synchronized int getReceiveBufferSize() throws SocketException {
        return underlyingSocket.getReceiveBufferSize();
    }

    public void setKeepAlive(boolean on) throws SocketException {
        underlyingSocket.setKeepAlive(on);
    }

    public boolean getKeepAlive() throws SocketException {
        return underlyingSocket.getKeepAlive();
    }

    public void setTrafficClass(int tc) throws SocketException {
        underlyingSocket.setTrafficClass(tc);
    }

    public int getTrafficClass() throws SocketException {
        return underlyingSocket.getTrafficClass();
    }

    public void setReuseAddress(boolean on) throws SocketException {
        underlyingSocket.setReuseAddress(on);
    }

    public boolean getReuseAddress() throws SocketException {
        return underlyingSocket.getReuseAddress();
    }

    public synchronized void close() throws IOException {
        underlyingSocket.close();
    }

    public void shutdownInput() throws IOException {
        underlyingSocket.shutdownInput();
    }

    public void shutdownOutput() throws IOException {
        underlyingSocket.shutdownOutput();
    }

    public String toString() {
        return "WrappedSocket (" + underlyingSocket.toString() + ")";
    }

    public boolean isConnected() {
        return underlyingSocket.isConnected();
    }

    public boolean isBound() {
        return underlyingSocket.isBound();
    }

    public boolean isClosed() {
        return underlyingSocket.isClosed();
    }

    public boolean isInputShutdown() {
        return underlyingSocket.isInputShutdown();
    }

    public boolean isOutputShutdown() {
        return underlyingSocket.isOutputShutdown();
    }

    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
        underlyingSocket.setPerformancePreferences(connectionTime, latency, bandwidth);
    }

    /* SSLSocket implementation */

    @Override
    public String[] getSupportedCipherSuites() {
        // Not implemented
        return new String[0];
    }

    @Override
    public String[] getEnabledCipherSuites() {
        // Not implemented
        return new String[0];
    }

    @Override
    public void setEnabledCipherSuites(String[] strings) {
        // Not implemented
    }

    @Override
    public String[] getSupportedProtocols() {
        // Not implemented
        return new String[0];
    }

    @Override
    public String[] getEnabledProtocols() {
        // Not implemented
        return new String[0];
    }

    @Override
    public void setEnabledProtocols(String[] strings) {
        // Not implemented
    }

    @Override
    public SSLSession getSession() {
        // Not implemented
        return null;
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener handshakeCompletedListener) {
        // Not implemented
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener handshakeCompletedListener) {
        // Not implemented
    }

    @Override
    public void startHandshake() throws IOException {

    }

    @Override
    public void setUseClientMode(boolean b) {
        // Not implemented
    }

    @Override
    public boolean getUseClientMode() {
        return true;
    }

    @Override
    public void setNeedClientAuth(boolean b) {
        // Not implemented
    }

    @Override
    public boolean getNeedClientAuth() {
        // Not implemented
        return false;
    }

    @Override
    public void setWantClientAuth(boolean b) {
        // Not implemented
    }

    @Override
    public boolean getWantClientAuth() {
        // Not implemented
        return false;
    }

    @Override
    public void setEnableSessionCreation(boolean b) {
        // Not implemented
    }

    @Override
    public boolean getEnableSessionCreation() {
        // Not implemented
        return false;
    }
}
