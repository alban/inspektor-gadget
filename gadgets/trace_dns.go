package main

import (
	"fmt"

	wapc "github.com/wapc/wapc-guest-tinygo"
)

func main() {
	wapc.RegisterFunctions(wapc.Functions{
		"column_name": column_name,
	})
}

func column_name(payload []byte) ([]byte, error) {
	//wapc.ConsoleLog(fmt.Sprintf("column_name called with %q\n", string(payload)))
	var str string
	for i := 0; i < len(payload); i++ {
		length := int(payload[i])
		if length == 0 {
			break
		}
		if i+1+length < len(payload) {
			str += string(payload[i+1:i+1+length]) + "."
		} else {
			wapc.ConsoleLog(fmt.Sprintf("invalid payload %+v\n", payload))
		}
		i += length
	}
	if string(str) == "wikipedia.org." {
		wapc.ConsoleLog("WASM(Goland): thanks you for visiting wikipedia.org.")
	}
	if string(str) == "example.com." {
		wapc.HostCall("ig", "event", "drop", []byte("example.com not allowed"))
		wapc.ConsoleLog("WASM(Goland): dropping example.com.")

		dstEndpoint, err := wapc.HostCall("ig", "event", "lookup_endpoints", []byte("dst"))
		if err != nil {
			wapc.ConsoleLog(fmt.Sprintf("The WASM module failed to lookup endpoint dst: %s\n", err))
			return nil, nil
		}
		wapc.ConsoleLog(fmt.Sprintf("WASM(Goland): looked up endpoint dst: %q\n", string(dstEndpoint)))
	}
	return []byte(str), nil
}
