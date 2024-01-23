package main

import (
	"fmt"

	"github.com/alexflint/go-arg"
	qrcode "github.com/pschlump/goqrcode"
	"github.com/xlzd/gotp"
)

func main() {
	var args struct {
		SecretKey string `arg:"required"`
		FileName  string `arg:"required"`
		UserName  string `arg:"required"`
	}
	arg.MustParse(&args)
	authotp := gotp.NewDefaultTOTP(args.SecretKey).ProvisioningUri(args.UserName, "VPNAuth")
	err := qrcode.WriteFile(authotp, qrcode.Medium, 256, args.FileName)
	if err != nil {
		fmt.Println("write error")
	}
	fmt.Printf("QR code %s generated successfully!\n", args.FileName)
}
