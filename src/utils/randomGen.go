package utils

import (
	"math/rand"
	"fmt"
)

func Gen32() string {
	var res string
	for i := 0; i < 32; i++ {
		res += string(rand.Intn(26) + 'a')
	}
	fmt.Println(res)
	return res
}
