package main

import (
	"fmt"
	"hexane_server/cmd"
)

func main() {
	if err := cmd.Run(); err != nil {
		fmt.Println(err)
	}
}
