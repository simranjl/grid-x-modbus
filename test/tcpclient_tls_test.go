package main 

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
	"os"
	"time"
	// "net"
	// "bytes"
	// "encoding/binary"
	// "slices"

	"github.com/grid-x/modbus"
)


func main() {
	fmt.Println("Modbus TCP Client Example")
}


const tRegisterNum uint16 = 0xCAFE
const qtyUint32 uint16 = 2
const tSentinelVal uint32 = 0xBADC0DE


// func createTLSServer(config *tls.Config, handler *modbus.TCPClientHandler)  {

// 	fmt.Println("createTLSServer called")

// 	ln, err := tls.Listen("tcp", "localhost:5802", config) 
// 	if err != nil {
// 		fmt.Printf("failed to create TLS listener: %v\n", err)
// 		return
// 	}

// 	defer ln.Close()
// 	fmt.Println("TLS server is listening on localhost:5802")


// 	acceptConnAndRespond := func(srvLn net.Listener) (error) {
// 		conn, err := srvLn.Accept()
// 		if err != nil {
// 			return fmt.Errorf("accepting server connection: %s", err)
// 		}

// 		readBuf := make([]byte, bytes.MinRead)
// 		n, err := conn.Read(readBuf)
// 		if err != nil {
// 			return fmt.Errorf("reading from server connection: %s", err)
// 		}

// 		const fnc = 4

// 		// Ensure that the request originates from the test.
// 		requestAdu, err := (handler).Decode(readBuf[:n])
// 		if err != nil {
// 			return fmt.Errorf("decoding ProtocolDataUnit: %s", err)
// 		}
// 		if requestAdu.FunctionCode != fnc {
// 			return fmt.Errorf("unexpected request function code (%v/%v)", requestAdu.FunctionCode, fnc)
// 		}
// 		transactionID := binary.BigEndian.Uint16(readBuf[0:2])
// 		unitID := readBuf[6]

// 		var expectData []byte
// 		expectData = binary.BigEndian.AppendUint16(expectData, tRegisterNum)
// 		expectData = binary.BigEndian.AppendUint16(expectData, qtyUint32)
// 		if !slices.Equal(expectData, requestAdu.Data) {
// 			return fmt.Errorf("unexpected request data (%v/%v)", requestAdu.Data, expectData)
// 		}

// 		const sizeUint32 = 4
// 		var writeData []byte
// 		writeData = append(writeData, sizeUint32)
// 		writeData = binary.BigEndian.AppendUint32(writeData, tSentinelVal)
// 		// pdu := &modbus.ProtocolDataUnit{
// 		// 	FunctionCode: fnc,
// 		// 	Data:         writeData,
// 		// }
// 		// responseData, err := (handler).Encode(pdu)
// 		// if err != nil {
// 		// 	return fmt.Errorf("encoding ProtocolDataUnit: %s", err)
// 		// }

// 		response := make([]byte, 7+len(writeData))
// 		binary.BigEndian.PutUint16(response[0:2], transactionID) // Transaction ID
// binary.BigEndian.PutUint16(response[2:4], 0)             // Protocol ID
// binary.BigEndian.PutUint16(response[4:6], uint16(1+1+len(writeData))) // Length: UnitID + FunctionCode + Data
// response[6] = unitID
// response[7] = fnc
// copy(response[8:], writeData)

// 		fmt.Printf("respnse data returned: %v\n", response)

// 		_, err = conn.Write(response)
// 		return err
// 	}

// 	if err := acceptConnAndRespond(ln); err != nil {
// 		fmt.Printf("error while accepting and responding to connection: %s", err)
// 		return
// 	}

// }


func BenchmarkReadHoldingRegisters(b *testing.B) {
	certPEM, err := os.ReadFile("certs/operator-client.cert.pem")
	if err != nil {
		fmt.Printf("%s", err)
	}
	keyPERM, err := os.ReadFile("certs/operator-client.key.pem")
	if err != nil {
		fmt.Printf("%s", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPERM)
	if err != nil {
		fmt.Printf("%s", err)
	}

	serverCertPEM, err := os.ReadFile("certs/server.cert.pem")
	if err != nil {
		fmt.Printf("%s", err)
	}
	serverKeyPEM, err := os.ReadFile("certs/server.key.pem")
	if err != nil {
		fmt.Printf("%s", err)
	}
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		fmt.Printf("%s", err)
	}

	rootCAs := x509.NewCertPool()
	tempCert, _ := x509.ParseCertificate(serverCert.Certificate[0])
	rootCAs.AddCert(tempCert)


	clientCAs := x509.NewCertPool()
	clientCert, _ := x509.ParseCertificate(cert.Certificate[0])
	clientCAs.AddCert(clientCert)


	client_tls_option := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName: "localhost",
		RootCAs: rootCAs,
	}

	// create TLS config for server
	server_tls_option := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: clientCAs,
	}

	handler := modbus.NewTCPClientHandler("localhost:5802", modbus.WithTLSConfig(client_tls_option))
	handler.Timeout = 10 * time.Second


	go modbus.CreateTLSServer(server_tls_option)
	client := modbus.NewClient(handler)

	ctx := context.Background()
	handler.Connect(ctx)
	defer handler.Close()

	count := 0
	for i := 0; i < b.N; i++ {
		if (count ==  1) {
			break
		}
		temp, _ := client.ReadInputRegisters(ctx, tRegisterNum, (qtyUint32))
		fmt.Printf("Read Input Registers: %v\n", temp)
		// got := binary.BigEndian.Uint32(temp)
		// if (got != tSentinelVal) {
		// 	b.Error("did not expected value")
		// }
		
		count++
	}

}

