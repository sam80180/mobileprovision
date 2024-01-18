package mobileprovision

import (
	"fmt"
	"os"
	"testing"
)

func Test(t *testing.T) {
	file := "embedded.mobileprovision"
	b, err := os.ReadFile(file)
	if err != nil {
		t.Error(err)
	}
	mp, err := Load(b)
	if err != nil {
		t.Error(err)
	}
	b, _ = mp.ToJSON()
	fmt.Println(string(b))
	b, _ = mp.ToPlist()
	fmt.Println(string(b))

}
