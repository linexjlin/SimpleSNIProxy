//
// Very Simple SNIProxy with GO Language 
// Code by Jioh L. Jung(ziozzang@gmail.com)
//
package main

import (
  "flag"
  "net"
  "io"
  "log"
  "strconv"
  "bufio"
  "container/list"
  "strings"
)


func on_disconnect(dst io.WriteCloser, con_chk chan int){
  // On Close-> Force Disconnect another pair of connection.
  dst.Close()
  con_chk <- 1
}

func ioReflector(dst io.WriteCloser, src io.Reader, con_chk chan int) {
  // Reflect IO stream to another.
  defer on_disconnect(dst, con_chk)
  written, _ := io.Copy(dst, src)
  log.Printf("Written %d", written) //TODO: Update to Metric Info
  dst.Close()
  con_chk <- 1
}

func handle_simpleHTTP(conn net.Conn) {
  headers := bufio.NewReader(conn)
  hostname := ""
  readLines := list.New()
  for {
    bytes, _, error := headers.ReadLine()
    if error != nil {
      conn.Close()
      return
    }
    line := string(bytes)
    log.Printf("%s", line)
    readLines.PushBack(line)
    if line == "" {
      // End of HTTP headers
      break
    }
    //Check Host Header.
    if strings.HasPrefix(line, "Host: ") {
      hostname = strings.TrimPrefix(line, "Host: ")
    }
  }
  

  backend, error := net.Dial("tcp", hostname + ":80")
  if error != nil {
    log.Fatal("Couldn't connect to backend", error)
    conn.Close()
    return
  }

  for element := readLines.Front(); element != nil; element = element.Next() {
    line := element.Value.(string)
    backend.Write([]byte(line))
    backend.Write([]byte("\n"))
    log.Printf("> %s", line)
  }

  con_chk := make(chan int)
  go ioReflector(backend, conn, con_chk)
  go ioReflector(conn, backend, con_chk)
}


func handle_simpleSNI(conn net.Conn) {
  // Simple SNI Protocol : SNI Handling Code from https://github.com/gpjt/stupid-proxy/
  firstByte := make([]byte, 1)
  _, error := conn.Read(firstByte)
  if error != nil {
    log.Printf("Couldn't read first byte :-(")
    return
  }
  if firstByte[0] != 0x16 {
    log.Printf("Not TLS :-(")
  }

  versionBytes := make([]byte, 2)
  _, error = conn.Read(versionBytes)
  if error != nil {
    log.Printf("Couldn't read version bytes :-(")
    return
  }
  if versionBytes[0] < 3 || (versionBytes[0] == 3 && versionBytes[1] < 1) {
    log.Printf("SSL < 3.1 so it's still not TLS v%d.%d", versionBytes[0], versionBytes[1])
    return
  }

  restLengthBytes := make([]byte, 2)
  _, error = conn.Read(restLengthBytes)
  if error != nil {
    log.Printf("Couldn't read restLength bytes :-(")
    return
  }
  restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

  rest := make([]byte, restLength)
  _, error = conn.Read(rest)
  if error != nil {
    log.Printf("Couldn't read rest of bytes")
    return
  }

  current := 0

  handshakeType := rest[0]
  current += 1
  if handshakeType != 0x1 {
    log.Printf("Not a ClientHello")
    return
  }

  // Skip over another length
  current += 3
  // Skip over protocolversion
  current += 2
  // Skip over random number
  current += 4 + 28
  // Skip over session ID
  sessionIDLength := int(rest[current])
  current += 1
  current += sessionIDLength

  cipherSuiteLength := (int(rest[current]) << 8) + int(rest[current+1])
  current += 2
  current += cipherSuiteLength

  compressionMethodLength := int(rest[current])
  current += 1
  current += compressionMethodLength

  if current > restLength {
    log.Println("no extensions")
    return
  }

  // Skip over extensionsLength
  // extensionsLength := (int(rest[current]) << 8) + int(rest[current + 1])
  current += 2

  hostname := ""
  for current < restLength && hostname == "" {
    extensionType := (int(rest[current]) << 8) + int(rest[current+1])
    current += 2

    extensionDataLength := (int(rest[current]) << 8) + int(rest[current+1])
    current += 2

    if extensionType == 0 {
      // Skip over number of names as we're assuming there's just one
      current += 2

      nameType := rest[current]
      current += 1
      if nameType != 0 {
        log.Printf("Not a hostname")
        return
      }
      nameLen := (int(rest[current]) << 8) + int(rest[current+1])
      current += 2
      hostname = string(rest[current : current+nameLen])
    }

    current += extensionDataLength
  }

  if hostname == "" {
    log.Printf("No hostname")
    return
  }

  backend, error := net.Dial("tcp", hostname + ":443")
  if error != nil {
    log.Fatal("Couldn't connect to backend", error)
    backend.Close()
    return
  }

  backend.Write(firstByte)
  backend.Write(versionBytes)
  backend.Write(restLengthBytes)
  backend.Write(rest)

  con_chk := make(chan int)
  go ioReflector(backend, conn, con_chk)
  go ioReflector(conn, backend, con_chk)
}

func listen_defered(term chan int){
}

func start_listen(ip string, port int, handle func(net.Conn), term chan int) {
  defer listen_defered(term)

  listener, error := net.Listen("tcp", ip + ":" + strconv.Itoa(port))
  if error != nil {
    log.Printf("Couldn't start listening", error)
    return
  }
  log.Printf("Started proxy on %s:%d -- listening", ip, port)
  for {
    connection, error := listener.Accept()
    if error != nil {
      log.Printf("Accept error", error)
      return
    }
    log.Printf("From: %s", connection.RemoteAddr().String())
    go handle(connection)
  }
}

func main() {
  bindip := flag.String("bindip", "0.0.0.0", "Bind Specific IP Address")
  flag.Parse()

  tchan := make (chan int)
  go start_listen(*bindip, 80, handle_simpleHTTP, tchan)
  go start_listen(*bindip, 443, handle_simpleSNI, tchan)
  <- tchan
}

