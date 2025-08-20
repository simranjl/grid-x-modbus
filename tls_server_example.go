package modbus

import (
	"crypto/tls"
	"net"
	"bytes"
	"encoding/binary"
	"slices"
	"fmt"
)


func CreateTLSServer(config *tls.Config) {
	const tRegisterNum uint16 = 0xCAFE
	const qtyUint32 uint16 = 2
	const tSentinelVal uint32 = 0xBADC0DE
	fmt.Println("createTLSServer called")

	ln, err := tls.Listen("tcp", "localhost:5802", config) 
	if err != nil {
		fmt.Printf("failed to create TLS listener: %v\n", err)
		return
	}

	defer ln.Close()
	fmt.Println("TLS server is listening on localhost:5802")

	acceptConnAndRespond := func(srvLn net.Listener) (error) {
		conn, err := srvLn.Accept()
		if err != nil {
			return fmt.Errorf("accepting server connection: %s", err)
		}

		readBuf := make([]byte, bytes.MinRead)
		n, err := conn.Read(readBuf)
		if err != nil {
			return fmt.Errorf("reading from server connection: %s", err)
		}

		const fnc = 4

		// Ensure that the request originates from the test.
		requestAdu, err := (&tcpPackager{}).Decode(readBuf[:n])
		if err != nil {
			return fmt.Errorf("decoding ProtocolDataUnit: %s", err)
		}
		if requestAdu.FunctionCode != fnc {
			return fmt.Errorf("unexpected request function code (%v/%v)", requestAdu.FunctionCode, fnc)
		}

		var expectData []byte
		expectData = binary.BigEndian.AppendUint16(expectData, tRegisterNum)
		expectData = binary.BigEndian.AppendUint16(expectData, qtyUint32)
		if !slices.Equal(expectData, requestAdu.Data) {
			return fmt.Errorf("unexpected request data (%v/%v)", requestAdu.Data, expectData)
		}

		const sizeUint32 = 4
		var writeData []byte
		writeData = append(writeData, sizeUint32)
		writeData = binary.BigEndian.AppendUint32(writeData, tSentinelVal)
		pdu := &ProtocolDataUnit{
			FunctionCode: fnc,
			Data:         writeData,
		}
		response, err := (&tcpPackager{}).Encode(pdu)
		if err != nil {
			return fmt.Errorf("encoding ProtocolDataUnit: %s", err)
		}

		fmt.Printf("respnse data returned: %v\n", response)

		_, err = conn.Write(response)
		return err
	}

	// for {
	// 	if err := acceptConnAndRespond(ln); err != nil {
	// 		fmt.Printf("error while accepting and responding to connection: %s", err)
	// 		return
	// 	}
	// }
	if err := acceptConnAndRespond(ln); err != nil {
		fmt.Printf("error while accepting and responding to connection: %s", err)
		return
	}
}


// func CreateTLSServer(config *tls.Config, handler *TCPClientHandler) {
// 	const tRegisterNum uint16 = 0xCAFE
// 	const qtyUint32 uint16 = 2
// 	const tSentinelVal uint32 = 0xBADC0DE
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
// 		pdu := &ProtocolDataUnit{
// 			FunctionCode: fnc,
// 			Data:         writeData,
// 		}
// 		response, err := (handler).Encode(pdu)
// 		if err != nil {
// 			return fmt.Errorf("encoding ProtocolDataUnit: %s", err)
// 		}

// 		fmt.Printf("respnse data returned: %v\n", response)

// 		_, err = conn.Write(response)
// 		return err
// 	}

// 	for {
// 		if err := acceptConnAndRespond(ln); err != nil {
// 			fmt.Printf("error while accepting and responding to connection: %s", err)
// 			return
// 		}
// 	}
// }