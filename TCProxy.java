package com.umarabdul.networking.tcproxy;

import java.net.*;
import java.io.*;
import java.util.ArrayList;
import com.umarabdul.wrapper.socketwrapper.SocketWrapper;
import com.umarabdul.util.argparser.ArgParser;


/**
* A static TCP proxy in Java for tunneling TCP connections.
* @author Umar Abdul
* @version 1.0
* @since 2020
*/

public class TCProxy{

  private boolean active = false;
  private int workers = 0;
  private String lhost;
  private int lport;
  private String rhost;
  private int rport;
  private int backlog = 100;
  private int timeout = 50; // read timeout in milliseconds, must be very small for faster routing.
  private int blockSize = 9999; // maximum bytes to read at single socket read operation, the bigger the value, the more memory is used, the faster traffic is routed.
  private ArrayList<String> filter;
  private ServerSocket server = null;
  private int verbosity = 0;

  /**
  * TCProxy constructor.
  * @param lhost Host to listen on.
  * @param lport Port to listen on.
  * @param rhost Host to route connections to.
  * @param rport Port to route connections to.
  */
  public TCProxy(String lhost, int lport, String rhost, int rport){

    this.lhost = lhost;
    this.lport = lport;
    this.rhost = rhost;
    this.rport = rport;
    filter = new ArrayList<String>();
  }

  /**
  * Obtain the address of remote host.
  * @return Remote host address.
  */
  public String getRhost(){
    return rhost;
  }

  /**
  * Obtain the port number of remote host.
  * @return Remote port.
  */
  public int getRport(){
    return rport;
  }

  /**
  * Obtain the address used for listening.
  * @return Listening host.
  */
  public String getLhost(){
    return lhost;
  }

  /**
  * Obtain the port number used for listening.
  * @return Listening port.
  */
  public int getLport(){
    return lport;
  }

  /**
  * Check if the proxy is running. Useful when the class was executed as a separate thread.
  * @return {@code true} if the proxy is active.
  */
  public boolean isActive(){
    return active;
  }

  /**
  * Check if there is an active connection being routed.
  * @return {@code true} if there is an active connection.
  */
  public boolean hasWorkers(){
    return (workers > 0 ? true : false);
  }

  /**
  * Obtain the number of active connections being routed.
  * @return Number of active connections being routed.
  */
  public int getWorkers(){
    return workers;
  }

  /**
  * Add a list of IPs to connection whitelist. This will enable host filtering and any host not in the list will be blocked.
  * @param hosts A list of IPs to whitelist.
  */
  public void addWhitelist(String[] hosts){

    for (String s : hosts){
      if (!(filter.contains(s)))
        filter.add(s);
    }
  }

  /**
  * Clear the list of whitelisted hosts and disable host filtering.
  */
  public void clearWhitelist(){
    filter.clear();
  }

  /**
  * Set socket connection backlog for the proxy server.
  * @param backlog Backlog to use.
  */
  public void setBacklog(int backlog){
    this.backlog = backlog;
  }

  /**
  * Set socket read timeout used during routing.
  * @param timeout Timeout in milliseconds. The smaller the value, the faster traffic is routed.
  */
  public void setTimeout(int timeout){
    this.timeout = timeout;
  }

  /**
  * Set block size for socket read operations. Large value consumes more memory but allows for faster routing.
  * @param blockSize Block size to use.
  */
  public void setBlockSize(int blockSize){
    this.blockSize = blockSize;
  }

  /**
  * Set verbosity of server outputs.
  * @param verbosity Value of verbosity to use, where {@code 0 = none, 1 = verbose, 2 = very verbose}.
  */
  public void setVerbosity(int verbosity){
    this.verbosity = verbosity;
  }

  /**
  * Start the proxy server.
  */
  public void start(){

    if (active)
      return;
    try{
      server = new ServerSocket(lport, backlog, InetAddress.getByName(lhost));
      server.setSoTimeout(300); // timeout for accepting connections.
    }catch(Exception e){
      e.printStackTrace();
      return;
    }
    active = true;
    Socket client;
    Thread t;
    if (verbosity > 0)
      System.out.println(String.format("[*] Listening for connections on: %s:%d...", lhost, lport));
    while (active){
      try{
        client = server.accept();
        t = new Thread(new Router(client));
        t.start();
      }catch(SocketTimeoutException e){
        continue;
      }catch(IOException e1){
        e1.printStackTrace();
        active = false;
      }
    }
    try{
      server.close();
    }catch(IOException e){}
  }

  /**
  * This inner class handles data routing for a single connection.
  */
  private class Router implements Runnable{

    private Socket client;

    public Router(Socket client){
      this.client = client;
    }

    @Override
    public void run(){

      String chost = client.getRemoteSocketAddress().toString();
      if (filter.size() > 0){ // filter connection.
        boolean allow = false;
        for (String s : filter){
          if (chost.startsWith("/"+s+":")){
            allow = true;
            break;
          }
        }
        if (!(allow)){
          if (verbosity > 1)
            System.out.println(String.format("[!] Connection from %s rejected!", chost));
          return;
        }
      }
      workers++;
      SocketWrapper rconn;
      SocketWrapper cconn;
      try{
        rconn = new SocketWrapper(rhost, rport, false);
        rconn.getSocket().setSoTimeout(timeout);
        cconn = new SocketWrapper(client);
        cconn.getSocket().setSoTimeout(timeout);
      }catch(Exception e){
        workers--;
        return;
      }
      if (verbosity > 0)
        System.out.println(String.format("[+] Tunneling:  %s  ==>  %s:%d...", chost, rhost, rport));
      // Route.
      byte[] buffer = null;
      while (active){
        buffer = rconn.readBytes(blockSize);
        if (buffer == null)
          break;
        if (buffer.length > 0){
          if (verbosity > 1)
            System.out.println(String.format("[*] %s:%d (%d bytes)  ==>  %s...", rhost, rport, buffer.length, chost));
          if (!(cconn.writeBytes(buffer, 0, buffer.length)))
            break;
        }
        buffer = cconn.readBytes(blockSize);
        if (buffer == null)
          break;
        if (buffer.length > 0){
          if (verbosity > 1)
            System.out.println(String.format("[*] %s (%d bytes)  ==>  %s:%d...", chost, buffer.length, rhost, rport));
          if (!(rconn.writeBytes(buffer, 0, buffer.length)))
            break;
        }
      }
      try{
        rconn.getSocket().close();
        cconn.getSocket().close();
      }catch(IOException e){}
      workers--;
    }
  }

  /**
  * Start a static proxy using command-line arguments.
  * @param args Command-line arguments: listening host, listening port, remote host, and remote port.
  */
  public static void main(String[] args){

    String helpPage = "TCProxy v1.0 - Static TCP Proxy  (Author: https://github.com/UmarAbdul01)\n"+
                      "       Usage: tcproxy --lhost <host:port> --rhost <host:port> [options]\n"+
                      "     Options:\n"+
                      "           -l|--lhost      <host:port>      :  Address to listen on\n"+
                      "           -r|--rhost      <host:port>      :  Remote address to route to\n"+
                      "           -b|--blocksize  <int>            :  Bytes to read per socket cycle\n"+
                      "           -w|--whitelist  <host1,host2,..> :  Hosts to whitelist\n"+
                      "           -v|--verbosity  <int>            :  verbosity level (default: 1)\n"+
                      "           -h|--help                        :  Print this help page";
    ArgParser agp = new ArgParser(args);
    agp.setAlias("lhost", "l");
    agp.setAlias("rport", "r");
    agp.setAlias("blocksize", "b");
    agp.setDefault("blocksize", "9999");
    agp.setAlias("whitelist", "w");
    agp.setAlias("verbosity", "v");
    agp.setDefault("verbosity", "1");
    if (agp.hasArg("-h") || agp.hasArg("--help")){
      System.out.println(helpPage);
      return;
    }
    if (!(agp.hasKWarg("lhost") && agp.hasKWarg("rhost"))){
      System.out.println(helpPage);
      return;
    }
    String lhost = agp.getString("lhost").split(":")[0];
    int lport = Integer.parseInt(agp.getString("lhost").split(":")[1]);
    String rhost = agp.getString("rhost").split(":")[0];
    int rport = Integer.parseInt(agp.getString("rhost").split(":")[1]);
    int blocksize = agp.getInt("blocksize");
    int verbosity = agp.getInt("verbosity");
    String whitelist = agp.getString("whitelist");

    TCProxy proxy = new TCProxy(lhost, lport, rhost, rport);
    proxy.setVerbosity(verbosity);
    proxy.setBlockSize(blocksize);
    if (whitelist != null)
      proxy.addWhitelist(whitelist.split(","));
    proxy.start();
  }

}